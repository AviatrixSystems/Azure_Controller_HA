
import logging
import azure.functions as func
from azure.identity import ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.storage.blob import BlobServiceClient
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.network.v2021_05_01.models import SecurityRule

import os
import sys
import time
from datetime import datetime
import pdb
import json
import threading
import urllib.request
import urllib.error
import urllib.parse
import requests
from retry import retry
import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)

MAX_LOGIN_TIMEOUT = 800
WAIT_DELAY = 30

INITIAL_SETUP_WAIT = 180
INITIAL_SETUP_DELAY = 10

INITIAL_SETUP_API_WAIT = 20
MAXIMUM_BACKUP_AGE = 24 * 3600 * 3  # 3 days

mask = lambda input: input[0:5] + '*' * 15 if isinstance(input, str) else ''

tenant_id = os.environ["avx_tenant_id"]
client_id = os.environ["avx_client_id"]
secret_key = os.environ["avx_secret_key"]
func_client_id = os.environ["func_client_id"]
storage_name = os.environ["storage_name"]
container_name = os.environ["container_name"]


class AvxError(Exception):
    """ Error class for Aviatrix exceptions"""

logging.warning('Loading function:\n')
start_time = datetime.now()


class TerminateVMThread(threading.Thread):
    """ Thread class to stop Azure VM """
    def __init__(self, resource_group, vm_name):
        threading.Thread.__init__(self)
        self.resource_group = resource_group
        self.vm_name = vm_name
    def run(self):
        logging.warning("- Terminating %s in resource group %s\n" % (self.vm_name,self.resource_group))
        sys.stdout.flush()
        terminate_vm(self.resource_group, self.vm_name)
        logging.warning("  Terminated successfully\n")
        sys.stdout.flush()

class VmScaleSet():
    def __init__(self, vm_ss_client, resource_group, scaleSetName):
        self.vm_ss_client = vm_ss_client
        self.resource_group = resource_group
        self.scaleSetName = scaleSetName
        self.vmScaleSet = vm_ss_client.get(resource_group, scaleSetName)
        self.sku = self.vmScaleSet.sku

    def getSku(self):
        return self.sku

    def updateSku(self):
        try:
            self.vmScaleSet.sku.capacity = 1
            response = self.vm_ss_client.begin_create_or_update(self.resource_group,self.scaleSetName,self.vmScaleSet)
            response.wait()
            if response.status() == 'Succeeded': 
                logging.warning("  Updated sku capacity: %s\n" % str(self.vmScaleSet.sku.capacity))
                # returns {'additional_properties': {}, 'name': 'Standard_A4_v2', 'tier': 'Standard', 'capacity': 1}
                return self.sku
        except Exception as err:
            logging.warning(str(err))


#### As a prevalidation :
# 1. Make sure eip is asscosiated with controller
# 2. Make sure instance exists if N?A start from updating capacity -- Need to think of getting EIP info
# 3. Make sure of using this class only if unhealthy instance exists
class VmNetInt():
    def __init__(self, resource_group, network_client, vm_intf_name):
        self.resource_group = resource_group
        self.network_client = network_client
        self.vm_intf_name = vm_intf_name
        self.Pri_intf_conf = self.network_client.network_interfaces.get(resource_group,vm_intf_name)
        self.sg_name = self.Pri_intf_conf.network_security_group.id.split('/')[-1]
        self.ipConfName = self.Pri_intf_conf.name
        self.subnetID = self.Pri_intf_conf.ip_configurations[0].subnet.id
        self.location = self.Pri_intf_conf.location
        self.AvxPrivIntIP = self.Pri_intf_conf.ip_configurations[0].private_ip_address
        self.AvxPrivIntID = self.Pri_intf_conf.id
        self.AvxPubIntID = self.Pri_intf_conf.ip_configurations[0].public_ip_address.id
        self.AvxPubIntName = self.Pri_intf_conf.ip_configurations[0].public_ip_address.id.split('/')[-1]
        self.Pub_intf_conf = self.network_client.public_ip_addresses.get(self.resource_group,self.AvxPubIntName)
        self.AvxPubIntIP = self.Pub_intf_conf.ip_address
        
    def rmPubIntIPAssoc(self):
        """ Removes public IP association before vm termination """
        inf_conf_model = self.Pri_intf_conf
        inf_conf_model.ip_configurations[0].public_ip_address = None
        try:
            logging.warning("- Dissociating %s : %s from %s" % (self.AvxPubIntName,self.AvxPubIntIP, self.AvxPrivIntIP))
            response = self.network_client.network_interfaces.begin_create_or_update( self.resource_group, self.vm_intf_name, inf_conf_model)
            response.wait()
            if response.status() == 'Succeeded':        
                logging.warning("  Dissociate completed successfully\n")
        except Exception as err:
            logging.warning(str(err))

    def addPubIntIPAssoc(self,old_public_ip_name):
        """ Associates old public IP to the new vm """
        params = {'id' : old_public_ip_name}
        inf_conf_model = self.Pri_intf_conf
        inf_conf_model.ip_configurations[0].public_ip_address = params
        try:
            logging.warning("- Associating %s with %s" % (old_public_ip_name.split('/')[-1], self.AvxPrivIntIP))
            response = self.network_client.network_interfaces.begin_create_or_update( self.resource_group, self.vm_intf_name, inf_conf_model)
            response.wait()
            if response.status() == 'Succeeded':
                logging.warning("  Associate completed successfully\n")
        except Exception as err:
            logging.warning(str(err))

    def deletePubIntIP(self):
        """ Deletes the public IP """
        try:
            print ("- Deleting newly created %s : %s from %s" % (self.AvxPubIntName,self.AvxPubIntIP,self.resource_group))
            response = self.network_client.public_ip_addresses.begin_delete( self.resource_group, self.AvxPubIntName)
            response.wait()
            if response.status() == 'Succeeded':   
                logging.warning("  Deleted public ip successfully\n")
        except Exception as err:
            logging.warning(str(err))

class LbConf():
    def __init__(self, lb_client, resource_group, network_client, lb_name):
        self.resource_group = resource_group
        self.lb_name = lb_name
        self.network_client = network_client
        self.lb_client_get = lb_client.get(self.resource_group,self.lb_name)
        self.location = self.lb_client_get.location
        self.lb_fe_name = self.lb_client_get.frontend_ip_configurations[0].name
        self.lb_be_name = self.lb_client_get.backend_address_pools[0].name
        self.lb_be_id = self.lb_client_get.backend_address_pools[0].id
        self.lb_be_rules = self.lb_client_get.backend_address_pools[0].load_balancing_rules
        self.lb_be_type = self.lb_client_get.backend_address_pools[0].type
        self.lb_public_ip_name = self.lb_client_get.frontend_ip_configurations[0].public_ip_address.id.split('/')[-1]
        self.lb_public_ip = self.network_client.public_ip_addresses.get(self.resource_group,self.lb_public_ip_name)
        self.lb_public_ip_prefix = self.lb_public_ip.ip_address
        self.lb_be_conf = self.network_client.load_balancer_backend_address_pools.get(self.resource_group, self.lb_name, self.lb_be_name)


def terminate_vm(vm_client, resource_group, vm_name):
    """ Terminates a vm in the specified resource group """
    try:
        logging.warning("- Terminating instance %s from resource group %s" % (vm_name,resource_group))
        response = vm_client.begin_delete(resource_group, vm_name)
        response.wait()
        if response.status() == 'Succeeded':
            logging.warning("  Terminated instance successfully\n")
    except Exception as err:
        logging.warning(str(err))

def aviatrix_vm_scale_set(vm_ss_client, resource_group):
    vmSclaeSetLst = vm_ss_client.list(resource_group)
    for vmSclaeSet in vmSclaeSetLst:
        #### Searching the VM scale set name by Aviatrix
        if 'Aviatrix' in vmSclaeSet.name:
            return vmSclaeSet.name

def vm_scale_set_vm_info(vm_client,resource_group, scaleSetName):
    vm_name = ''
    vm_nic_name = ''
    vmSclaeSetVmsLst = vm_client.list(resource_group)
    for vmSclaeSetVms in vmSclaeSetVmsLst:
        #### Searching the VM name by appending scaleset name + _
        if scaleSetName + '_' in vmSclaeSetVms.name:
            vm_name = vmSclaeSetVms.name
            vm_nic_name = vmSclaeSetVms.network_profile.network_interfaces[0].id.split('/')[-1]
    return vm_name,vm_nic_name

def login_to_controller(ip_addr, username, pwd):
    """ Logs into the controller and returns the cid"""
    base_url = "https://" + ip_addr + "/v1/api"
    url = base_url + "?action=login&username=" + username + "&password=" + \
          urllib.parse.quote(pwd, '%')
    logging.warning(url)
    try:
        response = requests.get(url, verify=False)
    except Exception as err:
        logging.warning("  Can't connect to controller with elastic IP %s. %s\n" % (ip_addr,
                                                                      str(err)))
        raise AvxError(str(err)) from err
    response_json = response.json()
    try:
        cid = response_json.pop('CID')
    except KeyError as err:
        logging.warning("  Unable to create session. {}\n".format(err))
        raise AvxError("  Unable to create session. {}\n".format(err)) from err
    return cid

def check_security_group_access(network_client, resource_group, sg_name):
    vmSgLst = network_client.network_security_groups.get(resource_group,sg_name)
    for rules in vmSgLst.security_rules:
        if rules.protocol == 'TCP' and rules.source_address_prefix == '*' and rules.direction == 'Inbound' and rules.destination_port_range == "443":
            logging.warning("  Access for Function inbound exists")
            return True
        else:
            logging.warning("  Access for Function inbound does not exist")
            return False

def delete_security_rule(network_client, resource_group, sg_name):
    try:
        sgRuleDelete = network_client.security_rules.begin_delete(resource_group,sg_name,'temp-nsg')
        sgRuleDelete.wait()
        if sgRuleDelete.status() == 'Succeeded':
            logging.warning("  Temp SG rule deleted sucessfully")
    except Exception as err:
        logging.warning(str(err)) 
        

def create_security_rule(network_client, resource_group, sg_name):
    vmSgLst = network_client.network_security_groups.get(resource_group,sg_name)
    security_rule = SecurityRule( protocol='Tcp', source_address_prefix='*', 
                              source_port_range="*", destination_port_range="443", priority=100,
                              destination_address_prefix='*', access='Allow', direction='Inbound', name = 'temp-nsg')
    vmSgLst.security_rules.append(security_rule)
    try:
        sgRuleCreate = network_client.network_security_groups.begin_create_or_update(resource_group, sg_name, parameters=vmSgLst)
        sgRuleCreate.wait()
        if sgRuleCreate.status() == 'Succeeded':
            logging.warning("  Creating Temp SG rule")
    except Exception as err:
        logging.warning(str(err)) 

@retry(Exception, tries=5, delay=30)
def run_initial_setup(ip_addr, ctrl_version, pwd):
    """ Boots the fresh controller to the specific version"""
    #### Need to reauth when retry happens so calling in CID inside the method
    cid = login_to_controller(ip_addr, "admin", pwd)
    response_json = get_initial_setup_status(ip_addr, cid)

    if response_json.get('return') is True:
        logging.warning("  Initial setup is already done. Skipping..\n")
        return True
    logging.warning("  Initialization required.\n")
    post_data = {"target_version": ctrl_version,
                 "action": "initial_setup",
                 "subaction": "run"}
    logging.warning("- Trying to run initial setup %s" % str(post_data))
    post_data["CID"] = cid
    base_url = "https://" + ip_addr + "/v1/api"

    try:
        # If no timeout, the connection hangs so retry in 6+1 min(i.e 7min taken for intialitizing) 
        response = requests.post(base_url, data=post_data, verify=False, timeout=360)
    except requests.exceptions.Timeout:
        logging.warning("  Retrying in 30 sec...\n")
        raise Exception
    except requests.exceptions.ConnectionError as err:
        if "Remote end closed connection without response" in str(err):
            logging.warning("  Server closed the connection while executing initial setup API."
                  " Ignoring response")
            response_json = {'return': True, 'reason': 'Warning!! Server closed the connection'}
        else:
            raise AvxError("  Failed to execute initial setup: " + str(err)) from err
    else:
        response_json = response.json()
        # Controllers running 6.4 and above would be unresponsive after initial_setup

    time.sleep(INITIAL_SETUP_API_WAIT)

    if response_json.get('return') is True:
        logging.warning("  Successfully initialized the controller")
    else:
        raise AvxError("  Could not bring up the new controller to the "
                       "specific version")
    return False

def get_initial_setup_status(ip_addr, cid):
    """ Get status of the initial setup completion execution"""

    logging.warning("- Checking initial setup status")
    base_url = "https://" + ip_addr + "/v1/api"
    post_data = {"CID": cid,
                 "action": "initial_setup",
                 "subaction": "check"}

    try:
        response = requests.post(base_url, data=post_data, verify=False)
    except requests.exceptions.ConnectionError as err:
        logging.warning(str(err))
        return {'return': False, 'reason': str(err)}
    return response.json()

def set_admin_email(controller_ip,cid,admin_email):
    """ add_admin_email_addr" API is supported by all controller versions since 2.6 """

    base_url = "https://%s/v1/api" % controller_ip
    post_data = {"action": "add_admin_email_addr",
                 "CID": cid,
                 "admin_email": admin_email}

    payload_with_hidden_password = dict(post_data)
    payload_with_hidden_password["CID"] = "************"
    logging.warning("- Creating admin email: \n" +
        str(json.dumps(obj=payload_with_hidden_password, indent=4)))

    try:
        response = requests.post(base_url, data=post_data, verify=False)
    except requests.exceptions.ConnectionError as err:
        if "Remote end closed connection without response" in str(err):
            logging.warning("  Server closed the connection while executing create account API."
                  " Ignoring response")
            output = {"return": True, 'reason': 'Warning!! Server closed the connection'}
            time.sleep(INITIAL_SETUP_DELAY)
        else:
            output = {"return": False, "reason": str(err)}
    else:
        output = response.json()

    return output

def retrieve_controller_version(version_file,container_client):
    """ Get the controller version from backup file"""
    logging.warning("  Retrieving version from file " + str(version_file))
    s3c = container_client.get_blob_client(version_file)
    try:
        with open('/tmp/version_ctrlha.txt', 'wb') as data:
            s3c.download_blob().readinto(data)
                        
    except Exception as err:
        logging.warning(str(err))
        logging.warning("  The object does not exist.")
        raise

    if not os.path.exists('/tmp/version_ctrlha.txt'):
        raise AvxError("Unable to open version file")

    with open("/tmp/version_ctrlha.txt") as fileh:
        buf = fileh.read()
    logging.warning("  Retrieved version " + str(buf))

    if not buf:
        raise AvxError("  Version file is empty")
    logging.warning("  Parsing version")

    # TODO: Starting 6.5.2608(6.5c), ctrl_version should return buf[12:]
    try:
        ctrl_version = ".".join(((buf[12:]).split("."))[:-1])
    except (KeyboardInterrupt, IndexError, ValueError) as err:
        raise AvxError("Could not decode version") from err
    else:
        logging.warning("  Parsed version sucessfully " + str(ctrl_version))
        logging.warning("")
        return ctrl_version

def is_backup_file_is_recent(backup_file,container_client):
    """ Check if backup file is not older than MAXIMUM_BACKUP_AGE """
    try:
        s3c = container_client.get_blob_client(backup_file)
        try:
            file_obj = s3c.get_blob_properties()
        except AvxError as err:
            logging.warning(str(err))
            return False

        age = time.time() - file_obj.last_modified.timestamp()
        if age < MAXIMUM_BACKUP_AGE:
            logging.warning("- Succesfully validated Backup file age\n")
            return True
        logging.warning(f"  File age {age} is older than the maximum allowed value of {MAXIMUM_BACKUP_AGE}")
        return False
    except Exception as err:
        logging.warning(f"  Checking backup file age failed due to {str(err)}")
        return False

def set_admin_password(controller_ip,cid,old_admin_password,new_admin_password):
    """ Set admin password """

    base_url = "https://%s/v1/api" % controller_ip

    post_data = {
        "action": "change_password",
        "CID": cid,
        "account_name": "admin",
        "user_name": "admin",
        "old_password": old_admin_password,
        "password": new_admin_password
    }

    payload_with_hidden_password = dict(post_data)
    payload_with_hidden_password["password"] = "************"
    payload_with_hidden_password["CID"] = "************"
    logging.warning("- Changing admin credentials: \n" +
        str(json.dumps(obj=payload_with_hidden_password, indent=4)))

    try:
        response = requests.post(base_url, data=post_data, verify=False)
    except requests.exceptions.ConnectionError as err:
        if "Remote end closed connection without response" in str(err):
            logging.warning("  Server closed the connection while executing create account API."
                  " Ignoring response")
            output = {"return": True, 'reason': 'Warning!! Server closed the connection'}
            time.sleep(INITIAL_SETUP_DELAY)
        else:
            output = {"return": False, "reason": str(err)}
    else:
        output = response.json()

    return output

def create_cloud_account(creds, cid, controller_ip, account_name, email):
    """ Create a temporary account to restore the backup"""

    logging.warning("- Creating temporary account")
    base_url = "https://%s/v1/api" % controller_ip
    post_data = {"action": "setup_account_profile",
                 "account_name": account_name,
                 "cloud_type": 8,
                 "account_email": email,
                 "arm_subscription_id": creds['subscription_id'],
                 "arm_application_endpoint": creds['tenant_id'],
                 "arm_application_client_id": creds['client_id'],
                 "arm_application_client_secret":creds['client_secret']}

    logging.warning("- Create account with data %s\n" % str(post_data))
    post_data["CID"] = cid
    post_data["arm_application_client_secret"] = creds['client_secret']

    try:
        response = requests.post(base_url, data=post_data, verify=False)
    except requests.exceptions.ConnectionError as err:
        if "Remote end closed connection without response" in str(err):
            logging.warning("  Server closed the connection while executing create account API."
                  " Ignoring response")
            output = {"return": True, 'reason': 'Warning!! Server closed the connection'}
            time.sleep(INITIAL_SETUP_DELAY)
        else:
            output = {"return": False, "reason": str(err)}
    else:
        output = response.json()
        logging.warning(output)

    return output

def restore_ctrl_backup(creds, controller_ip, cid, storage, container, blob):
    # restore backup configuration on controller
    ### the filename is based on private ip of the controller
    ### if there are a lot of restores and controller changes
    ### it could be possible that we might use a wrong/old one
    ### best to check the timestamp and make sure that the backup is <= 24 hour old

    base_url = "https://%s/v1/api" % controller_ip
    post_data = {"action": "restore_cloudx_config",
                 "cloud_type": "8",
                 "storage_name": storage,
                 "container_name": container,
                 "file_name": blob,
                 "arm_subscription_id": creds['subscription_id'],
                 "arm_application_endpoint": creds['tenant_id'],
                 "arm_application_client_id": creds['client_id']
                }
    logging.warning("- Trying to restore backup account with data %s \n" %
        str(json.dumps(obj=post_data, indent=4)))

    post_data["CID"] = cid
    post_data["arm_application_client_secret"] = creds['client_secret']

    try:
        response = requests.post(base_url, data=post_data, verify=False)
    except requests.exceptions.ConnectionError as err:
        if "Remote end closed connection without response" in str(err):
            logging.warning("  Server closed the connection while executing create account API."
                  " Ignoring response")
            output = {"return": True, 'reason': 'Warning!! Server closed the connection'}
            time.sleep(INITIAL_SETUP_DELAY)
        else:
            output = {"return": False, "reason": str(err)}
    else:
        output = response.json()
        logging.warning(output)

    return output

def main(req: func.HttpRequest, context: func.Context) -> func.HttpResponse:
#def main(req, context):
    logging.warning('Python HTTP trigger function processed a request.')    
    logging.warning(f"invocation_id : {context.invocation_id}")
    req_body = req.get_json()
    # logging.warning(f'temp_count : {os.environ["temp_count"]}')
    # os.environ["temp_count"] = str(int(os.environ["temp_count"]) + 1)
    headers = {"invocation_id": context.invocation_id, "alert_status": req_body['data']['status']}
    if not req_body['data']['status'] == 'Activated':
        logging.warning(f"Alert status type: {req_body['data']['status']}")
        return func.HttpResponse(
                "HA failover event is not triggered",
                headers=headers, status_code=501)

    lb_name = req_body['data']['context']['resourceName']
    rg = req_body['data']['context']['resourceGroupName']
    logging.info("###########")
    logging.warning(f'lb_name:{lb_name}')
    logging.warning(f'rg_name:{rg}')
    logging.warning(f'func_client_id:{func_client_id}')
    logging.warning(f'tenant_id:{tenant_id}')
    logging.warning(f'avx_client_id:{client_id}')
    logging.warning(f'storage_name:{storage_name}')
    logging.warning(f'container_name:{container_name}')
    logging.info("###########")

    credentials = DefaultAzureCredential(managed_identity_client_id = func_client_id)
    subscription_client = SubscriptionClient(credentials)
    subscription = next(subscription_client.subscriptions.list())
    subscription_id = subscription.subscription_id
    
    # Obtain the management object for resources, using the credentials from the CLI login.
    resource_client = ResourceManagementClient(credentials, subscription_id)
    network_client = NetworkManagementClient(credentials, subscription_id)
    compute_client = ComputeManagementClient(credentials, subscription_id)
    blob_service_client = BlobServiceClient("https://" + storage_name + ".blob.core.windows.net",credentials)
    #### Storage Blob Data Reader, Storage Queue Data Reader permissions required to read the blob data
    container_client = blob_service_client.get_container_client(container_name)
    
    cred = {
        'subscription_id': subscription_id,
        'tenant_id': tenant_id,
        'client_id': client_id,
        'client_secret': secret_key
    }
    
    vm_scaleset_client = compute_client.virtual_machine_scale_sets
    vm_res_client = compute_client.virtual_machines
    lb_res_client = network_client.load_balancers

    # Get Scaleset Name
    #vmScaleSetName = aviatrix_vm_scale_set(vm_scaleset_client, rg)
    vmScaleSetName = os.environ["scaleset_name"]

    # Get Scaleset attributes
    vm_scale_set = VmScaleSet(vm_scaleset_client, rg, vmScaleSetName)

    # Get VM info in a Scaleset 
    ins_name, private_nic_name = vm_scale_set_vm_info(vm_res_client, rg, vmScaleSetName)
    logging.warning(f'ins_name:{ins_name}')
    logging.warning(f'private_nic_name:{private_nic_name}')
    avx_int_conf = VmNetInt(rg,network_client,private_nic_name)
    logging.warning(f'avx_int_conf:{avx_int_conf}')
    old_pub_intf_id = avx_int_conf.AvxPubIntID
    logging.warning(f'old_pub_intf_id:{old_pub_intf_id}')
    logging.warning(avx_int_conf.AvxPubIntID)

    # Check if blob backup file is recent and able to access blob storage
    blob_file = "CloudN_" + avx_int_conf.AvxPrivIntIP + "_save_cloudx_config.enc"

    if not is_backup_file_is_recent(blob_file,container_client):
        raise AvxError(f"  HA event failed. Backup file does not exist or is older"
                    f" than {MAXIMUM_BACKUP_AGE}")

    version_file = "CloudN_" + avx_int_conf.AvxPrivIntIP + "_save_cloudx_version.txt"
    logging.warning(f"- Controller version file name is {version_file}")
    ctrl_version = retrieve_controller_version(version_file, container_client)

    # Get LoadBalacer config prior to EIP removal
    lb = LbConf(lb_res_client, rg, network_client, lb_name)
    lb_public_ip_prefix = lb.lb_public_ip_prefix

    # Remove EIP Association
    avx_int_conf.rmPubIntIPAssoc()

    # Terminate unhealthy VM
    vm_detail = vm_res_client.get(rg, ins_name, expand='instanceView')

    try:
        #if vm_detail.instance_view.statuses[1].code == 'PowerState/running':
            # terminate_vm_thread = TerminateVMThread(rg, vm_detail.name)
            # terminate_vm_thread.start()
        terminate_vm(vm_res_client, rg, vm_detail.name)
    except Exception as err:
        logging.warning(str(err))
        logging.warning("  There are no running VM's in a scale set ")

    # Update Manual autoscale.
    # sku = vm_scale_set.getSku()
    # sku.capacity = 1
    logging.warning("- Increasing sku capacity -> 1")
    vm_scale_set.updateSku()

    #### needs to be more dynamic.. wait time for scaleset to spin up one more instance
    time.sleep(WAIT_DELAY) 

    # Get new VM info in a Scaleset 
    N_ins_name, N_private_nic_name = vm_scale_set_vm_info(vm_res_client, rg,vmScaleSetName)
    N_avx_int_conf = VmNetInt(rg,network_client,N_private_nic_name)
    N_pub_intf_conf = N_avx_int_conf.Pub_intf_conf
    int_sg_name = N_avx_int_conf.sg_name

    temp_access = False
    # Check if https access for functions exist 
    sg_access = check_security_group_access(network_client, rg, int_sg_name)
    if not sg_access:
        create_security_rule(network_client, rg, int_sg_name)
        temp_access = True

    # Remove new public ip Association with new instance
    N_avx_int_conf.rmPubIntIPAssoc()

    # Add old public ip Association to the new instance
    N_avx_int_conf.addPubIntIPAssoc(old_pub_intf_id)

    # Delete the detached public ip Association to the new instance
    N_avx_int_conf.deletePubIntIP()

    try:
        total_time = 0
        while total_time <= MAX_LOGIN_TIMEOUT:
            try:
                cid = login_to_controller(lb_public_ip_prefix, "admin", N_avx_int_conf.AvxPrivIntIP)
                logging.warning("- Connected to loadbalancer and created new session with CID {}\n".format(mask(cid)))
            except Exception as err:
                logging.warning(str(err))
                logging.warning("  Login failed, trying to connect loadbalancer front end ip %s again in %s" % (lb_public_ip_prefix, str(WAIT_DELAY)))
                total_time += WAIT_DELAY
                time.sleep(WAIT_DELAY)
            else:
                break

        if total_time >= MAX_LOGIN_TIMEOUT:
            logging.warning("  Could not login to the controller. Attempting to handle login failure")
            # handle_login_failure(controller_api_ip, client, lambda_client, controller_instanceobj,
            #                         context, eip)



        #### Need to include check for azure blob
        initial_setup_complete = run_initial_setup(lb_public_ip_prefix, ctrl_version , N_avx_int_conf.AvxPrivIntIP)
        temp_acc_name = "tempacc"
        total_time = 0
        sleep = False
        created_temp_acc = False
        created_prim_acc = False
        login_complete = False

        while total_time <= INITIAL_SETUP_WAIT:
            if sleep:
                logging.warning("  Waiting for safe initial setup completion, maximum of " +
                        str(INITIAL_SETUP_WAIT - total_time) + " seconds remaining\n")
                time.sleep(WAIT_DELAY)
            else:
                logging.warning(f"\n- {INITIAL_SETUP_WAIT - total_time} seconds remaining\n")
                sleep = True

            if not login_complete:
                # Need to login again as initial setup invalidates cid after waiting
                logging.warning("- Logging in again\n")
                try:
                    cid = login_to_controller(lb_public_ip_prefix, "admin", N_avx_int_conf.AvxPrivIntIP)
                except AvxError:  # It might not succeed since apache2 could restart
                    logging.warning("  Cannot connect to the controller\n")
                    sleep = False
                    time.sleep(INITIAL_SETUP_DELAY)
                    total_time += INITIAL_SETUP_DELAY
                    continue
                else:
                    login_complete = True

            if not initial_setup_complete:
                response_json = get_initial_setup_status(lb_public_ip_prefix, cid)
                logging.warning("  Initial setup status %s\n" % response_json)
                if response_json.get('return', False) is True:
                    initial_setup_complete = True

    ####Try and catch for each response
            if initial_setup_complete:
                #response_json = set_admin_email(lb_public_ip_prefix,cid,ADMIN_EMAIL)

                #response_json = set_admin_password(lb_public_ip_prefix,cid,N_avx_int_conf.AvxPrivIntIP,ADMIN_TEMP_PASSWORD)

                #response_json = create_cloud_account(cred, lb_public_ip_prefix, cid, temp_acc_name,ADMIN_EMAIL)

                response_json = restore_ctrl_backup(cred, lb_public_ip_prefix, cid, storage_name, container_name, blob_file)
                break
            
            else:
                total_time += WAIT_DELAY
                time.sleep(WAIT_DELAY)

    finally:
        logging.warning("\nLoading function completed !!")
        if temp_access:
            delete_security_rule(network_client, rg, int_sg_name)
        # end_time = datetime.now()
        # logging.warning('\nDuration: {}\n'.format(end_time - start_time))
        return func.HttpResponse(
                "Failover event completed successfully",
                headers=headers, status_code=200)