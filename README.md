[comment]: # "Auto-generated SOAR connector documentation"
# BigID Data Discovery

Publisher: BigID  
Connector Version: 1.0.0  
Product Vendor: BigiD  
Product Name: Discovery Foundation  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 5.3.5  

BigID is a next-gen data discovery and intelligence platform for the data you know and the data you don’t know

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2023 BigID"
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "  http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
Check out [BigID](https://bigid.com/) or the [BigID Data Intelligence
Platform](https://bigid.com/data-intelligence-platform/) for more information.  
  
The BigID Data Discovery App for Splunk SOAR provides functionality allowing business users to take
action on their data, regardless of the type or location. With actions for searching BigID's data
catalog, retrieving PII findings, executing a scan for given data sources and retrieving those scan
results, as well as retrieving BigID audit logs, business users will have an invaluable tool for
building robust playbooks to action and protect sensitive data.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Discovery Foundation asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**username** |  optional  | string | BigID Username
**password** |  optional  | password | BigID Password
**host** |  required  | string | BigID Host
**accessToken** |  optional  | password | BigID user access token

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[refresh session token](#action-refresh-session-token) - Refresh the session token  
[get catalog data objects](#action-get-catalog-data-objects) - Get a full list of all data objects and their characteristics.  
[get pii findings](#action-get-pii-findings) - Retrieve all PII findings for a given list of data sources  
[execute scan](#action-execute-scan) - Execute a scan for a given data source  
[get last scan result](#action-get-last-scan-result) - Retrieve the most recent scan result for the data source  
[get audit logs](#action-get-audit-logs) - Retrieve BigID audit logs  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'refresh session token'
Refresh the session token

Type: **generic**  
Read only: **False**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'get catalog data objects'
Get a full list of all data objects and their characteristics.

Type: **investigate**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter** |  optional  | search filter | string | 
**limit** |  optional  | pagination limit | numeric | 
**offset** |  optional  | number of records to skip | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.filter | string |  |  
action_result.parameter.limit | numeric |  |  
action_result.parameter.offset | numeric |  |  
action_result.status | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'get pii findings'
Retrieve all PII findings for a given list of data sources

Type: **investigate**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**data_sources** |  required  | Comma delimited list of data source names | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.data_sources | string |  |  
action_result.status | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'execute scan'
Execute a scan for a given data source

Type: **investigate**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**data_source_name** |  required  | Name of the data source | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.data_source_name | string |  |  
action_result.status | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'get last scan result'
Retrieve the most recent scan result for the data source

Type: **investigate**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**data_source_name** |  required  | Name of the data source | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.data_source_name | string |  |  
action_result.status | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'get audit logs'
Retrieve BigID audit logs

Type: **investigate**  
Read only: **False**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  