#!/usr/bin/env python

# Lock and Delete User Utility provides an ability to identify the Aurora PostgreSQL users login activity and identify
# them if they are eligible for locking or deleting as per the company standards

# Copyright 2019 Amazon.com, Inc. or its affiliates.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#    http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file.
# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

import psycopg2
import logging
import traceback
import boto3
import json
import sys
from botocore.exceptions import ClientError
from os import environ
import datetime

epoch = datetime.datetime.utcfromtimestamp(0)

# Get User's input via environment variable.
secret_name = environ.get('SECRET_NAME')
lock_interval_days = environ.get("LOCK_INTERVAL_DAYS")
delete_interval_days = environ.get("DELETE_INTERVAL_DAYS")
users_to_be_ignored = environ.get("IGNORE_USER_LIST")
log_level = environ.get("LOG_LEVEL")
https_proxy = environ.get("https_proxy")
http_proxy = environ.get("http_proxy")

# Set global level variables being used in multiple functions
secret = None
conn = None
database_type = None
lock_interval_milliseconds = 0
delete_interval_milliseconds = 0

if https_proxy == "None":
  environ.pop("https_proxy")
if http_proxy == "None":
  environ.pop("http_proxy")

if lock_interval_days is None:
   lock_interval_days = "0"

lock_interval_milliseconds = int(lock_interval_days) * 86400000

if delete_interval_days is None:
   delete_interval_days = "0"

delete_interval_milliseconds = int(delete_interval_days) * 86400000

if (users_to_be_ignored is None or users_to_be_ignored == "None"):
   users_to_be_ignored = []
else:
   users_to_be_ignored = json.loads(users_to_be_ignored)

if log_level is None:
   log_level = "INFO"

# Queries being used across the utility
fetch_users_pg_user = "SELECT usename FROM pg_user where usename not in ('rdsadmin','masteruser',"
endQuery = ")"

fetch_users_login_status = "SELECT * FROM user_login_status"

get_all_users_list = "SELECT usename FROM pg_user"

get_users_from_login_status = "SELECT username FROM user_login_status"

add_user = """ INSERT INTO user_login_status (username,last_login_time,status)
VALUES ( 'adduser' , (select now() - '1 day'::interval),'A');"""

delete_user = "DELETE FROM user_login_status WHERE username='deleteuser';"

extra_user_login = """INSERT INTO user_login_status (username,last_login_time)
VALUES ( 'extrauser' , now());"""

current_time = "SELECT now()"

create_table_user_login = """CREATE TABLE user_login_status (
username TEXT PRIMARY KEY,
last_login_time TIMESTAMPTZ DEFAULT now(),
status TEXT
);"""

create_table_user_job_st = """CREATE TABLE user_login_job_status (
	Instance_name TEXT,
	last_processed_time TIMESTAMPTZ
);"""

list_tables = """SELECT
   table_name
FROM
   information_schema.tables
WHERE
   table_type='BASE TABLE'
   AND
   table_schema='public'"""

check_table = [
    " SELECT EXISTS (SELECT 1 FROM   pg_tables WHERE  schemaname = 'public' AND    tablename = 'user_login_status');",
    "SELECT EXISTS (SELECT 1 FROM   pg_tables WHERE  schemaname = 'public' AND    tablename = 'user_login_job_status');"]

drop_tables = """ DROP TABLE IF EXISTS user_login_status;
DROP TABLE IF EXISTS user_login_job_status;"""

get_details_from_usr_job_status = "select * from user_login_job_status"

add_user_job_status = """INSERT INTO user_login_job_status (Instance_name,last_processed_time)
VALUES ( 'instance_name' , (select now() - '1 day'::interval));"""

get_last_login_timestamp = "select last_processed_time from user_login_job_status where Instance_name = 'instance_identifier'"

check_time = "select EXISTS (select true from user_login_status where username='userID' and last_login_time<'log_time');"

update_user_login_status = "UPDATE user_login_status SET last_login_time = 'update_time' WHERE username = 'userID';"

check_time_job_status = "select EXISTS (select true from user_login_job_status where Instance_name='instanceID' and last_processed_time<'log_time');"

update_user_login_job_status = "UPDATE user_login_job_status SET last_processed_time = 'update_time' WHERE Instance_name = 'instanceID';"

lock_user = "ALTER USER some_user CONNECTION LIMIT 0;"

lock_user_status_update = "UPDATE user_login_status SET status='newStatus' where username = 'userID';"

delete_inactive_user = "DROP USER some_user;"

active_user_count = "select count(1) from pg_stat_activity where usename='checkuser';"

# Log Level gets decided based upon user's input. Default is INFO.
logging.basicConfig()
logger = logging.getLogger("logger")
logging_level = "logging." + log_level
if log_level == "CRITICAL":
    logger.setLevel(logging.CRITICAL)
elif log_level == "ERROR":
    logger.setLevel(logging.ERROR)
elif log_level == "WARNING":
    logger.setLevel(logging.WARNING)
elif log_level == "DEBUG":
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

# Handler function gets called whenever the lambda function gets executed.
def handler(event, context):
    global secret
    secret = getSecret(secret_name) # Connect to RDS DB using a secret stored in secretes manager.
    try:
        global conn
        conn = makeConnection()
        if database_type == "APG":
            cluster_identifier = json.loads(secret)['dbClusterIdentifier']
            dbClusters = getClusterDetails(cluster_identifier)  # Retrieve specific cluster's detail

        createTablesIfAbsent() # Create utility specific tables if they don't already exist.

        if database_type == "APG":
            manageUsers(dbClusters[0]['MasterUsername'])  # Manage the users comparing user_login_status table with pg_user table.

        if database_type == "APG":
            manageClusterInstanceLoginTime(dbClusters[0])  # Get the logs for all the instances and store the latest time in the utility specific tables

        manageInactiveUsers()


    except:
        logErr("ERROR: Cannot retrieve query data.\n{}".format(
            traceback.format_exc()))
        raise
    finally:
        try:
            conn.close()
        except:
            pass

# Retrieves secrets value using boto3 API for secrets manager.
def getSecret(secretName):
    # If the secret is not defined, the program execution will be stopped.
    if (secretName is None):
       logger.error("Secret Name can't be null.")
       sys.exit()

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager'
    )

    try:
        logger.debug("Getting secrets information for " + secretName)
        get_secret_value_response = client.get_secret_value(
            SecretId=secretName
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        else:
            logger.error(e)
    # else:
    # Decrypts secret using the associated KMS CMK.
    # Depending on whether the secret is a string or binary, one of these fields will be populated.
    if 'SecretString' in get_secret_value_response:
        secret = get_secret_value_response['SecretString']
    return secret

# Returns the DB Connection object. DB Connection is made using the Secret value fetched from secretes manager.
def makeConnection():
    global conn
    global database_type
    data = json.loads(secret)
    endpoint = data['host']
    port = data['port']
    dbname = data['dbname']
    user = data['username']
    password = data['password']
    if 'dbClusterIdentifier' in data:
        database_type = "APG"
    else:
        database_type = "PG"
    conn_str = "host={0} dbname={1} user={2} password={3} port={4}".format(
        endpoint, dbname, user, password, port)
    conn = psycopg2.connect(conn_str)
    conn.autocommit = True
    return conn

# Retrieves cluster's detail using boto3 API for rds.
def getClusterDetails(cluster_identifier):
    logger.debug("Getting cluster details for " + cluster_identifier)

    rds = boto3.client('rds')
    response = rds.describe_db_clusters(
        DBClusterIdentifier=cluster_identifier)
    dbClusters = response['DBClusters']
    return dbClusters

# Creates utility specific tables to keep track of users login activity and login activity on specific instance.
def createTablesIfAbsent():
        user_login_status = fetchFromDatabase(check_table[0])
        user_login_status_exists = user_login_status[0][0]
        logger.debug("user_login_status table exists : " + str(user_login_status_exists))

        user_login_job_status = fetchFromDatabase(check_table[1])
        user_login_job_status_exists = user_login_job_status[0][0]
        logger.debug("user_login_job_status table exists : " + str(user_login_job_status_exists))

        if not user_login_status_exists:
            updateDatabase(create_table_user_login)
            logger.debug("Created user_login_status table")
        if not user_login_job_status_exists:
            updateDatabase(create_table_user_job_st)
            logger.debug("Created user_login_job_status table")

        result = updateDatabase(get_users_from_login_status)
        logger.debug("Currently available users in user_login_status table are: ")
        logger.debug(result)
        logger.debug("---------------------------------------------------------------")


        return {"body": str(), "headers": {}, "statusCode": 200,
            "isBase64Encoded": "false"}

# Manage the users comparing user_login_status table with pg_user table.
def manageUsers(master_user_name):

        # Get list of users from pg_user table except rdsadmin, master user and some ignored user (if they are set in env variable)
        pg_user_query = fetch_users_pg_user.replace("masteruser", master_user_name)
        if users_to_be_ignored is not []:
            for user in users_to_be_ignored:
                pg_user_query = pg_user_query + "'" + user + "',"
        k = pg_user_query.rfind(",")
        pg_user_query = pg_user_query[:k] + endQuery
        available_pg_users = fetchFromDatabase(pg_user_query)
        pg_users_list = []
        for user in available_pg_users:
            pg_users_list.append(user[0])
        logger.debug("Available users in pg_user table are :")
        logger.debug(pg_users_list)

        # Get list of users from user_login_status table
        available_users_login_status = fetchFromDatabase(get_users_from_login_status)
        login_users_list = []
        for login_user in available_users_login_status:
            login_users_list.append(login_user[0])
        logger.debug("Available users in user_login_status table are :")
        logger.debug(login_users_list)

        # Add users which are present in pg_user but not in user_login_status
        copy_users_list = set(pg_users_list) - set(login_users_list)
        for user in copy_users_list:
            add_user_query = add_user.replace("adduser", user)
            updateDatabase(add_user_query)

        # Delete users which are present in user_login_status but not in pg_user
        delete_users_list = set(login_users_list) - set(pg_users_list)
        for user in delete_users_list:
            delete_user_query = delete_user.replace("deleteuser", user)
            updateDatabase(delete_user_query)

        # Final list of users after syncing the user_login_status table with pg_user table.
        result = fetchFromDatabase(get_users_from_login_status)
        logger.debug("Available users in user_login_status table after syncing the users from pg_user table are :")
        logger.debug(result)
        logger.debug("---------------------------------------------------------------")


        return {"body": str(), "headers": {}, "statusCode": 200,
            "isBase64Encoded": "false"}

# Get the logs for all the instances and store the latest time in the utility specific tables
def manageClusterInstanceLoginTime(cluster):
    instanceInfoDict = {}
    userLoginTimeDict = {}

    # Get list of instances from user_login_job_status table.
    user_login_job_status_info = fetchFromDatabase(get_details_from_usr_job_status)
    logger.debug("Current instances in the user_login_job_status are: ")
    for instanceInfo in user_login_job_status_info:
        instanceInfoDict[instanceInfo[0]] = instanceInfo[1]
        logger.debug(instanceInfo[0] + " with last login time as " + str(instanceInfo[1]))
    logger.debug("---------------------------------------------------------------")

    # Check if all the instances are available in the user_login_job_status table, if not add them to the table
    instanceFound = False
    for clusterMember in cluster['DBClusterMembers']:
        for instanceKey in instanceInfoDict.keys():
            if instanceKey == clusterMember['DBInstanceIdentifier']:
                instanceFound = True
                break
        if not instanceFound:
            logger.debug(clusterMember['DBInstanceIdentifier'] + " is not found in the user_login_job_status table")
            logger.debug("Adding the instance : " + clusterMember['DBInstanceIdentifier'] + " to user_login_job_status table")
            add_usr_job_status_query = add_user_job_status.replace('instance_name', clusterMember['DBInstanceIdentifier'])
            updateDatabase(add_usr_job_status_query)
        else:
            logger.debug(clusterMember['DBInstanceIdentifier'] + " is found in the user_login_job_status table")

        get_last_login_timestamp_query = get_last_login_timestamp.replace('instance_identifier',
                                                                      clusterMember['DBInstanceIdentifier'])
        last_login_timestamp = fetchFromDatabase(get_last_login_timestamp_query)

    naive = last_login_timestamp[0][0].replace(tzinfo=None)
    dateInMili = unixTimeMillis(naive)
    logs = boto3.client('logs')
    logGroupName = "/aws/rds/cluster/" + cluster['DBClusterIdentifier'] + "/postgresql"

    # Retrieve the logs for a specific instance from cloudwatch starting the last login time.
    marker = None
    while True:
        paginator = logs.get_paginator('filter_log_events')
        response_iterator = paginator.paginate(
            logGroupName=logGroupName,
            filterPattern='"connection authorized:" - "user=rdsadmin"',
            startTime=dateInMili,
            PaginationConfig={
                'PageSize': 10,
                'StartingToken': marker})
        for page in response_iterator:
            events = page['events']
            for event in events:
                message = event['message']
                user = (message.split(" ")[6]).split("=")[1]
                if user not in userLoginTimeDict:
                    userLoginTimeDict[user] = event['timestamp']
                else:
                    if userLoginTimeDict.get(user) < event['timestamp']:
                        userLoginTimeDict[user] = event['timestamp']

        try:
            if 'nextToken' not in page:
                break
            marker = page['NextToken']
        except KeyError:
            sys.exit()

    logger.debug("Latest login time for the available users are: ")
    for user, latest_time in userLoginTimeDict.items():
        time = datetime.datetime.fromtimestamp(latest_time / 1000.0)
        logger.debug("UserID : " + user + "   " + "Last login time to any instance :" + str(time))

    logger.debug("---------------------------------------------------------------")
    updateUserLoginStatus(userLoginTimeDict)
    updateUserLoginJobStatus(userLoginTimeDict, cluster['DBClusterIdentifier'])

    result = fetchFromDatabase(fetch_users_login_status)
    logger.debug("Current users with last login time in the user_login_status are: ")
    for item in result:
        logger.debug(item[0] + "  :  " + str(item[1]))
    logger.debug("---------------------------------------------------------------")

    result1 = fetchFromDatabase(get_details_from_usr_job_status)
    logger.debug("Current instances with last login time in the user_login_job_status are: ")
    for item in result1:
        logger.debug(item[0] + "  :  " + str(item[1]))
    logger.debug("---------------------------------------------------------------")

# Update the user_login_status table with the latest login timestamp for the users
def updateUserLoginStatus(userLoginTimeDict):
    logger.debug("Updating last login time for users if required")
    for user, last_time in userLoginTimeDict.items():
        time = datetime.datetime.fromtimestamp(last_time / 1000.0)
        check_time_query = check_time.replace('userID', user).replace('log_time', str(time))
        shouldUpdate = fetchFromDatabase(check_time_query)
        if shouldUpdate[0][0]:
            update_user_login_status_query = update_user_login_status.replace('update_time', str(time)).replace(
                'userID', user)
            logger.debug("Updating the last login time in user_login_status table for user :" + user)
            updateDatabase(update_user_login_status_query)

    logger.debug("---------------------------------------------------------------")

# Update the user_login_job_status table with the latest login timestamp for the instances
def updateUserLoginJobStatus(userLoginTimeDict, dbInstance):
    logger.debug("Updating last login time for instances if required")
    latest_time = 0;
    for user, last_time in userLoginTimeDict.items():
        if latest_time < last_time:
            latest_time = last_time
    time = datetime.datetime.fromtimestamp(latest_time / 1000.0)
    check_time_query = check_time_job_status.replace('instanceID', dbInstance).replace('log_time', str(time))
    shouldUpdate = fetchFromDatabase(check_time_query)
    if shouldUpdate[0][0]:
        update_user_login_job_status_query = update_user_login_job_status.replace('update_time', str(time)).replace(
            'instanceID',
            dbInstance)
        logger.debug("Updating the last login time in user_login_status table for instance :" + dbInstance)
        updateDatabase(update_user_login_job_status_query)

    logger.debug("---------------------------------------------------------------")

# Check if the users haven't logged in since the given time, lock/delete them as appropriate
def manageInactiveUsers():
    currentTime = fetchFromDatabase(current_time)
    users_list = fetchFromDatabase(fetch_users_login_status)
    count = 0
    if delete_interval_milliseconds > 0 or lock_interval_milliseconds > 0 :
        for user in users_list:
            if (delete_interval_milliseconds > 0 and unixTimeMillis(currentTime[0][0].replace(tzinfo=None)) - unixTimeMillis(
                    user[1].replace(tzinfo=None)) >= delete_interval_milliseconds):
                if(fetchFromDatabase(active_user_count.replace("checkuser",user[0]))[0][0] == 0): #Checking if the user has active connection going on
                    if(user[2] == 'A' or user[2] == 'L'):
                        updateDatabase(delete_inactive_user.replace('some_user', user[0]),user[0])
                        count += 1
                    elif (user[2] == 'R'):
                        logger.info("User " + user[0] + " is already marked as ready for delete. Please take an appropriate action.")
            elif (lock_interval_milliseconds > 0 and unixTimeMillis(currentTime[0][0].replace(tzinfo=None)) - unixTimeMillis(
                        user[1].replace(tzinfo=None)) >= lock_interval_milliseconds):
                if (user[2] == 'A'):
                    if (fetchFromDatabase(active_user_count.replace("checkuser", user[0]))[0][0] == 0):  # Checking if the user has active connection going on
                        updateDatabase(lock_user.replace('some_user', user[0]))
                        updateDatabase(lock_user_status_update.replace('userID', user[0]).replace('newStatus', 'L'))
                        logger.info("Locking user " + user[0])
                        count += 1
                    elif (user[2] == 'L'):
                        logger.info("User " + user[0] + " is already marked as locked. Please take an appropriate action.")

    if (count == 0):
        logger.info("No users to delete or lock. All users are active users.")


# Converts UTC time in Unix time.
def unixTimeMillis(dt):
    return int(float((dt - epoch).total_seconds() * 1000))

# Runs a given query
def runQuery(query, get_result, *args):
    result = None
    try:
        cursor = conn.cursor()

        try:
            logger.debug("Executing Query : " + query)
            cursor.execute(query)
            if get_result:
               result = cursor.fetchall()
            if args:
               for user in args:
                   delete_user_query = delete_user.replace("deleteuser", user[0])
                   updateDatabase(delete_user_query)
                   logger.info("Deleted user: " + user[0])
            cursor.close()
        except psycopg2.ProgrammingError:
             logErr("ERROR: Cannot execute cursor. There is a Programming Error.\n{}".format(
                traceback.format_exc()))
             raise
        except psycopg2.errors.DependentObjectsStillExist:
             logErr("ERROR: Dependencies exist. Can't delete the user\n{}".format(
                traceback.format_exc()))
             for user in args:
                 ready_for_delete_user_query = lock_user_status_update.replace('userID', user[0])
                 updateDatabase(ready_for_delete_user_query.replace('newStatus', 'R'))
                 logger.info("Marked user ready to delete: " + user[0])
        except:
            logErr("ERROR: Cannot execute cursor. \n{}".format(
                traceback.format_exc()))
            raise

    except:
        logErr("ERROR: Cannot connect to database from handler.\n{}".format(
            traceback.format_exc()))
        raise

    return result

# Method to execute Select queries
def fetchFromDatabase(query):
    return runQuery(query, True)

# Method to execute DDL, DML queries
def updateDatabase(query,*args):
    if not args:
        return runQuery(query, False)
    else:
        return runQuery(query, False,args)

def logErr(errmsg):
    logger.error(errmsg)

if __name__ == "__main__":
    handler(None, None)
