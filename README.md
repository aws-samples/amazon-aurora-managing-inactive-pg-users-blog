## Managing Inactive Aurora PostgreSQL Users

This repository is associated with the AWS Databases blog post titled "Managing Inactive Aurora PostgreSQL Users". This blog post provides Aurora PostgreSQL users a mechanism to identify inactive database users and lock or delete them as per the requirement. For example it can help you implement the following database security policy:

- All database users inactive for 90 days are locked
- All database users inactive for 180 days are deleted

The code in this repository consists of the following:

- CloudFormation template that creates a sample Lambda function
- Python code for the lambda function

The Lambda code looks at the Aurora PostgreSQL user connection events in the CloudWatch Logs and determines the last login time for each user. Based on this information it locks/deletes the user as per the policy.

Check out the blog post for details about the functionality and the setup instructions.


## License

This project is licensed under the Apache-2.0 License.

