import json
import logging
import os
import time
import azure.functions as func
import requests
import urllib3
from . import version
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient
from azure.storage.blob import BlobServiceClient
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)

default_wait_time_for_apache_wakeup = 300
WAIT_DELAY = 30
INITIAL_SETUP_DELAY = 10
MAXIMUM_BACKUP_AGE = 24 * 3600 * 3  # 3 days


class AviatrixException(Exception):
    def __init__(self, message="Aviatrix Error Message: ..."):
        super(AviatrixException, self).__init__(message)


def function_handler(event):
    aviatrix_api_version = event["aviatrix_api_version"]
    aviatrix_api_route = event["aviatrix_api_route"]
    tenant_id = event["tenant_id"]
    client_id = event["client_id"]
    vault_uri = event["vault_uri"]
    vault_secret = event["vault_secret"]
    func_client_id = event["func_client_id"]
    storage_name = event["storage_name"]
    container_name = event["container_name"]
    lb_name = event["lb_name"]
    rg = event["rg"]
    wait_time = default_wait_time_for_apache_wakeup

    credentials = DefaultAzureCredential(
        managed_identity_client_id=func_client_id)
    subscription_client = SubscriptionClient(credentials)
    subscription = next(subscription_client.subscriptions.list())
    subscription_id = subscription.subscription_id
    network_client = NetworkManagementClient(credentials, subscription_id)
    compute_client = ComputeManagementClient(credentials, subscription_id)
    blob_service_client = BlobServiceClient(
        f"https://{storage_name}.blob.core.windows.net", credentials)
    container_client = blob_service_client.get_container_client(container_name)
    secret_client = SecretClient(vault_url=vault_uri, credential=credentials)
    retrieved_secret = secret_client.get_secret(vault_secret)

    cred = {
        'subscription_id': subscription_id,
        'tenant_id': tenant_id,
        'client_id': client_id,
        'client_secret': retrieved_secret.value
    }

    vm_scaleset_client = compute_client.virtual_machine_scale_sets
    vm_res_client = compute_client.virtual_machines
    lb_res_client = network_client.load_balancers

    # Get Scaleset Name
    vmScaleSetName = os.environ["scaleset_name"]

    # Get Scaleset attributes
    vm_scale_set = VmScaleSet(vm_scaleset_client, rg, vmScaleSetName)

    # Get VM info in a Scaleset
    inst_name, private_nic_name = vm_scale_set_vm_info(
        vm_res_client, rg, vmScaleSetName)
    logging.info(f'inst_name:{inst_name}')
    logging.info(f'private_nic_name:{private_nic_name}')
    avx_int_conf = VmNetInt(rg, network_client, private_nic_name)
    logging.info(f'avx_int_conf:{avx_int_conf}')
    old_pub_intf_id = avx_int_conf.AvxPubIntID
    logging.info(f'old_pub_intf_id:{old_pub_intf_id}')
    logging.info(avx_int_conf.AvxPubIntID)

    # Check if blob backup file is recent and able to access blob storage
    blob_file = f"CloudN_{avx_int_conf.AvxPrivIntIP}_save_cloudx_config.enc"

    if not is_backup_file_is_recent(blob_file, container_client):
        raise AviatrixException(f"HA event failed. Backup file does not exist "
                                f"or is older than {MAXIMUM_BACKUP_AGE}")

    version_file = (
        f"CloudN_{avx_int_conf.AvxPrivIntIP}_save_cloudx_version.txt")
    logging.info(f"Controller version file name is {version_file}")
    ctrl_version = retrieve_controller_version(version_file, container_client)

    # Get LoadBalacer config prior to public ip removal
    lb = LbConf(lb_res_client, rg, network_client, lb_name)
    hostname = lb.lb_public_ip_prefix

    # Remove public ip Association
    avx_int_conf.rmPubIntIPAssoc()

    # Terminate unhealthy VM
    vm_detail = vm_res_client.get(rg, inst_name, expand='instanceView')

    try:
        terminate_vm(vm_res_client, rg, vm_detail.name)
    except Exception as err:
        logging.warning(str(err))
        logging.info("There are no running VM's in a scale set ")

    # Increasing sku capacity
    logging.info("Increasing sku capacity -> 1")
    vm_scale_set.updateSku()

    # Needs to be dynamic wait time for scaleset to spin up 1 more instance
    time.sleep(WAIT_DELAY)

    # Get new VM info in a Scaleset
    N_inst_name, N_private_nic_name = vm_scale_set_vm_info(
        vm_res_client, rg, vmScaleSetName)
    N_avx_int_conf = VmNetInt(rg, network_client, N_private_nic_name)
    # Check if https access for functions exist

    # Remove new public ip Association with new instance
    N_avx_int_conf.rmPubIntIPAssoc()

    # Add old public ip Association to the new instance
    N_avx_int_conf.addPubIntIPAssoc(old_pub_intf_id)

    # Delete the detached public ip Association to the new instance
    N_avx_int_conf.deletePubIntIP()

    # Wait until the rest API service of Aviatrix Controller is up and running
    logging.info(
        "START: Wait until API server of Aviatrix Controller is up and running"
    )

    api_endpoint_url = (
        f"https://{hostname}/{aviatrix_api_version}/{aviatrix_api_route}"
    )

    wait_until_controller_api_server_is_ready(
        hostname=hostname,
        api_version=aviatrix_api_version,
        api_route=aviatrix_api_route,
        total_wait_time=wait_time,
        interval_wait_time=10,
    )
    logging.info(
        "ENDED: Wait until API server of controller is up and running")

    # Login Aviatrix Controller with username:
    # Admin and password: private ip address and verify login
    logging.info(
        "START: Login Aviatrix Controller as admin using private ip address")
    response = login(
        api_endpoint_url=api_endpoint_url,
        username="admin",
        password=N_avx_int_conf.AvxPrivIntIP,
        hide_password=True,
    )

    verify_aviatrix_api_response_login(response=response)
    CID = response.json()["CID"]
    logging.info(
        "END: Login Aviatrix Controller as admin using private ip address")

    # Check if the controller has been initialized or not
    logging.info(
        "START: Check if Aviatrix Controller has already been initialized")
    is_controller_initialized = has_controller_initialized(
        api_endpoint_url=api_endpoint_url,
        CID=CID,
    )

    if is_controller_initialized:
        err_msg = "ERROR: Controller has already been initialized"
        logging.error(err_msg)
        raise AviatrixException(message=err_msg)

    logging.info(
        "END: Check if Aviatrix Controller has already been initialized")

    # Initial Setup for Aviatrix Controller by Invoking Aviatrix API
    logging.info("Start: Aviatrix Controller initial setup")
    response = run_initial_setup(
        api_endpoint_url=api_endpoint_url,
        CID=CID,
        target_version=ctrl_version,
    )
    verify_aviatrix_api_run_initial_setup(response=response)
    logging.info("End: Aviatrix Controller initial setup")

    # Wait until apache server of controller is up and running after
    # initial setup.
    logging.info(
        ("START: Wait until API server of Aviatrix Controller "
         "is up and running after initial setup")
    )
    wait_until_controller_api_server_is_ready(
        hostname=hostname,
        api_version=aviatrix_api_version,
        api_route=aviatrix_api_route,
        total_wait_time=wait_time,
        interval_wait_time=10,
    )
    logging.info(
        ("End: Wait until API server of Aviatrix Controller "
         "is up and running after initial setup")
    )

    # Re-login
    logging.info("START: Re-login")
    response = login(
        api_endpoint_url=api_endpoint_url,
        username="admin",
        password=N_avx_int_conf.AvxPrivIntIP,
    )
    verify_aviatrix_api_response_login(response=response)
    CID = response.json()["CID"]
    logging.info("END: Re-login")

    # Restore backup
    logging.info("START: Restore-Backup")
    restore_ctrl_backup(cred, hostname, CID, storage_name,
                        container_name, blob_file)
    logging.info("END: Restore-Backup")


def wait_until_controller_api_server_is_ready(
    hostname="123.123.123.123",
    api_version="v1",
    api_route="api",
    total_wait_time=300,
    interval_wait_time=10,
):
    payload = {"action": "login", "username": "test", "password": "test"}
    api_endpoint_url = f"https://{hostname}/{api_version}/{api_route}"

    # invoke the aviatrix api with a non-existed api
    # to resolve the issue where server status code is 200 but response
    # message is "Valid action required: login"
    # which means backend is not ready yet
    payload = {"action": "login", "username": "test", "password": "test"}
    remaining_wait_time = total_wait_time

    """ Variable Description: (time_spent_for_requests_lib_timeout)
    Description:
        * This value represents how many seconds for "requests" lib to timeout
          by default.
    Detail:
        * The value 20 seconds is actually a rough number
        * If there is a connection error and causing timeout when
          invoking--> requests.get(xxx), it takes about 20 seconds for
          requests.get(xxx) to throw timeout exception.
        * When calculating the remaining wait time, this value is considered.
    """
    time_spent_for_requests_lib_timeout = 20
    last_err_msg = ""
    while remaining_wait_time > 0:
        try:
            # Reset the checking flags
            response_status_code = -1
            is_apache_returned_200 = False
            is_api_service_ready = False

            # invoke a dummy REST API to Aviatrix controller
            response = requests.post(
                url=api_endpoint_url, data=payload, verify=False)

            # check response
            # if the server is ready, the response code should be 200.
            # there are two cases that the response code is 200
            #   case1 : return value is false and the reason message is
            #           "Valid action required: login",
            #           which means the server is not ready yet
            #   case2 : return value is false and the reason message is
            #           "username and password do not match",
            #           which means the server is ready
            if response is not None:
                response_status_code = response.status_code
                logging.info(f"Server status code is: "
                             f"{str(response_status_code)}")
                py_dict = response.json()
                if 'CID' in py_dict:
                    py_dict["CID"] = "*********"
                if response.status_code == 200:
                    is_apache_returned_200 = True

                response_message = py_dict["reason"]
                response_msg_indicates_backend_not_ready = ("Valid action "
                                                            "required")
                response_msg_request_refused = "RequestRefused"
                # case1:
                if (
                    py_dict["return"] is False
                    and (
                        response_msg_indicates_backend_not_ready
                        in response_message
                        or response_msg_request_refused in response_message
                        )
                ):
                    is_api_service_ready = False
                    logging.info(
                        f"Server is not ready, and the response is "
                        f":{response_message}")
                # case2:
                else:
                    is_api_service_ready = True
            # END outer if

            # if the response code is 200 and the server is ready
            if is_apache_returned_200 and is_api_service_ready:
                logging.info("Server is ready")
                return True
        except Exception as e:
            logging.exception(
                f"Aviatrix Controller {api_endpoint_url} is not available")
            last_err_msg = str(e)
            pass
            # END try-except

            # handle the response code is 404
            if response_status_code == 404:
                err_msg = (
                    f"Error: Aviatrix Controller returns error code: 404 for "
                    f"{api_endpoint_url}"
                )
                raise AviatrixException(
                    message=err_msg,
                )
            # END if

        # if server response code is neither 200 nor 404,
        # some other errors occurs
        # repeat the process till reaches case 2

        remaining_wait_time = (
            remaining_wait_time
            - interval_wait_time
            - time_spent_for_requests_lib_timeout
        )
        if remaining_wait_time > 0:
            time.sleep(interval_wait_time)
    # END while loop

    # if the server is still not ready after the default time
    # raise AviatrixException
    err_msg = (
        f"Aviatrix Controller {api_endpoint_url} is not available after "
        f"{str(total_wait_time)} seconds "
        f"Server status code is: {str(response_status_code)}. "
        f"The response message is: {last_err_msg}."
    )
    raise AviatrixException(
        message=err_msg,
    )


# END wait_until_controller_api_server_is_ready()

def verify_aviatrix_api_response_login(response=None):
    # if successfully login
    # response_code == 200
    # api_return_boolean == true
    # response_message = "authorized successfully"

    py_dict = response.json()
    if 'CID' in py_dict:
        py_dict["CID"] = "*********"
    logging.info(f"Aviatrix API response is {str(py_dict)}")

    response_code = response.status_code
    if response_code != 200:
        err_msg = (
            f"Fail to login Aviatrix Controller. The response code is "
            f"{response_code}"
        )
        raise AviatrixException(message=err_msg)

    api_return_boolean = py_dict["return"]
    if api_return_boolean is not True:
        err_msg = (
            f"Fail to Login Aviatrix Controller. The Response is "
            f"{str(py_dict)}"
        )
        raise AviatrixException(
            message=err_msg,
        )

    api_return_msg = py_dict["results"]
    expected_string = "authorized successfully"
    if (expected_string in api_return_msg) is not True:
        err_msg = (
            f"Fail to Login Aviatrix Controller. The Response is "
            f"{str(py_dict)}"
        )
        raise AviatrixException(
            message=err_msg,
        )


# End def verify_aviatrix_api_response_login()

def login(
    api_endpoint_url="https://123.123.123.123/v1/api",
    username="admin",
    password="********",
    hide_password=True,
):
    request_method = "POST"
    data = {"action": "login", "username": username, "password": password}
    logging.info(f"API endpoint url is : {api_endpoint_url}")
    logging.info(f"Request method is : {request_method}")

    # handle if the hide_password is selected
    if hide_password:
        payload_with_hidden_password = dict(data)
        payload_with_hidden_password["password"] = "************"
        logging.info(
            f"Request payload: "
            f"{str(json.dumps(obj=payload_with_hidden_password, indent=4))}")
    else:
        logging.info(f"Request payload: "
                     f"{str(json.dumps(obj=data, indent=4))}")

    # send post request to the api endpoint
    response = send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=data,
    )
    return response


# End def login()

def send_aviatrix_api(
    api_endpoint_url="https://123.123.123.123/v1/api",
    request_method="POST",
    payload=dict(),
    retry_count=5,
    timeout=None,
):
    response = None
    responses = list()
    request_type = request_method.upper()
    response_status_code = -1

    for i in range(retry_count):
        try:
            if request_type == "GET":
                response = requests.get(
                    url=api_endpoint_url, params=payload, verify=False
                )
                response_status_code = response.status_code
            elif request_type == "POST":
                response = requests.post(
                    url=api_endpoint_url, data=payload,
                    verify=False, timeout=timeout
                )
                response_status_code = response.status_code
            else:
                failure_reason = (f"ERROR : Bad HTTPS request type: "
                                  f"{request_type}")
                logging.error(failure_reason)
        except requests.exceptions.Timeout as e:
            logging.warning(f"WARNING: Request timeout... {str(e)}")
            responses.append(str(e))
        except requests.exceptions.ConnectionError as e:
            logging.warning(f"WARNING: Server is not responding... {str(e)}")
            responses.append(str(e))
        except Exception as e:
            logging.warning(f"HTTP request failed {str(e)}")
            # For error message/debugging purposes

        finally:
            if response_status_code == 200:
                return response
            elif response_status_code == 404:
                failure_reason = "ERROR: 404 Not Found"
                logging.error(failure_reason)

            # if the response code is neither 200 nor 404, retry process
            # the default retry count is 5, the wait for each retry is i
            # i           =  0  1  2  3  4
            # wait time   =     1  2  4  8

            if i + 1 < retry_count:
                logging.info("START: retry")
                logging.info("i == %d", i)
                wait_time_before_retry = pow(2, i)
                logging.info("Wait for: %ds for the next retry",
                             wait_time_before_retry)
                time.sleep(wait_time_before_retry)
                logging.info("ENDED: Wait until retry")
                # continue next iteration
            else:
                failure_reason = (
                    f"ERROR: Failed to invoke Aviatrix API. Exceed the max "
                    f"retry times. All responses are listed as follows: "
                    f"{str(responses)}"
                )
                raise AviatrixException(
                    message=failure_reason,
                )
            # END
    return response


# End def send_aviatrix_api()

def verify_aviatrix_api_run_initial_setup(response=None):
    if not response:
        return
    py_dict = response.json()
    if 'CID' in py_dict:
        py_dict["CID"] = "*********"
    logging.info(f"Aviatrix API response is: {str(py_dict)}")

    response_code = response.status_code
    if response_code != 200:
        err_msg = (
            f"Fail to run initial setup for the Aviatrix Controller. "
            f"The actual response code is "
            f"{str(response_code)}, which is not 200"
        )
        raise AviatrixException(message=err_msg)

    api_return_boolean = py_dict["return"]
    if api_return_boolean is not True:
        err_msg = (
            f"Fail to run initial setup for the Aviatrix Controller. "
            f"The actual api response is "
            f"{str(py_dict)}"
        )
        raise AviatrixException(message=err_msg)
    pass


# End def verify_aviatrix_api_run_initial_setup()

def has_controller_initialized(
    api_endpoint_url="123.123.123.123/v1/api",
    CID="ABCD1234",
):
    request_method = "GET"
    data = {"action": "initial_setup", "subaction": "check", "CID": CID}
    payload_with_hidden_password = dict(data)
    payload_with_hidden_password["CID"] = "************"
    logging.info(f"API endpoint url: {str(api_endpoint_url)}")
    logging.info(f"Request method is: {str(request_method)}")
    logging.info(
        f"Request payload is : "
        f"{str(json.dumps(obj=payload_with_hidden_password, indent=4))}")
    response = send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=data,
    )

    py_dict = response.json()
    if 'CID' in py_dict:
        py_dict["CID"] = "*********"
    logging.info(f"Aviatrix API response is: {str(py_dict)}")

    if py_dict["return"] is False and "not run" in py_dict["reason"]:
        return False
    else:
        return True


# End def has_controller_initialized()

# End def send_aviatrix_api()
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
            response = self.vm_ss_client.begin_create_or_update(
                self.resource_group, self.scaleSetName, self.vmScaleSet)
            response.wait()
            if response.status() == 'Succeeded':
                logging.info(f"Updated sku capacity: "
                             f"{str(self.vmScaleSet.sku.capacity)}\n")
                # returns {'additional_properties': {},
                # 'name': 'Standard_A4_v2',
                # 'tier': 'Standard',
                # 'capacity': 1}
                return self.sku
        except Exception as err:
            logging.warning(str(err))


# As a prevalidation :
# 1. Make sure eip is asscosiated with controller
# 2. Make sure instance exists if N?A start from updating capacity
# 3. Make sure of using this class only if unhealthy instance exists
class VmNetInt():
    def __init__(self, resource_group, network_client, vm_intf_name):
        self.resource_group = resource_group
        self.network_client = network_client
        self.vm_intf_name = vm_intf_name
        self.Pri_intf_conf = self.network_client.network_interfaces.get(
            resource_group, vm_intf_name)
        self.sg_name = self.Pri_intf_conf.network_security_group.id.split(
            '/')[-1]
        self.ipConfName = self.Pri_intf_conf.name
        self.subnetID = self.Pri_intf_conf.ip_configurations[0].subnet.id
        self.location = self.Pri_intf_conf.location
        self.AvxPrivIntIP = (
            self.Pri_intf_conf.ip_configurations[0].private_ip_address)
        self.AvxPrivIntID = self.Pri_intf_conf.id
        self.AvxPubIntID = (
            self.Pri_intf_conf.ip_configurations[0].public_ip_address.id)
        self.AvxPubIntName = (
            self.Pri_intf_conf.ip_configurations[0].public_ip_address.id.split(
                '/')[-1])
        self.Pub_intf_conf = self.network_client.public_ip_addresses.get(
            self.resource_group, self.AvxPubIntName)
        self.AvxPubIntIP = self.Pub_intf_conf.ip_address

    def rmPubIntIPAssoc(self):
        """ Removes public IP association before vm termination """
        inf_conf_model = self.Pri_intf_conf
        inf_conf_model.ip_configurations[0].public_ip_address = None
        try:
            logging.info(
                f"START: Dissociating {self.AvxPubIntName} : "
                f"{self.AvxPubIntIP} from {self.AvxPrivIntIP}")
            response = (
                self.network_client.network_interfaces.begin_create_or_update(
                    self.resource_group, self.vm_intf_name, inf_conf_model))
            response.wait()
            if response.status() == 'Succeeded':
                logging.info("End: Dissociating completed successfully\n")
        except Exception as err:
            logging.warning(str(err))

    def addPubIntIPAssoc(self, old_public_ip_name):
        """ Associates old public IP to the new vm """
        params = {'id': old_public_ip_name}
        inf_conf_model = self.Pri_intf_conf
        inf_conf_model.ip_configurations[0].public_ip_address = params
        try:
            logging.info(f"START: Associating "
                         f"{old_public_ip_name.split('/')[-1]} "
                         f" with {self.AvxPrivIntIP}")
            response = (
                self.network_client.network_interfaces.begin_create_or_update(
                    self.resource_group, self.vm_intf_name, inf_conf_model))
            response.wait()
            if response.status() == 'Succeeded':
                logging.info("End: Associating completed successfully\n")
        except Exception as err:
            logging.warning(str(err))

    def deletePubIntIP(self):
        """ Deletes the public IP """
        try:
            logging.info(
                f"START: Deleting newly created {self.AvxPubIntName} : "
                f"{self.AvxPubIntIP} from {self.resource_group}")
            response = self.network_client.public_ip_addresses.begin_delete(
                self.resource_group, self.AvxPubIntName)
            response.wait()
            if response.status() == 'Succeeded':
                logging.info("End: Deleting public ip successfully\n")
        except Exception as err:
            logging.warning(str(err))


class LbConf():
    def __init__(self, lb_client, resource_group, network_client, lb_name):
        self.resource_group = resource_group
        self.lb_name = lb_name
        self.network_client = network_client
        self.lb_client_get = lb_client.get(self.resource_group, self.lb_name)
        self.location = self.lb_client_get.location
        self.lb_fe_name = self.lb_client_get.frontend_ip_configurations[0].name
        self.lb_be_name = self.lb_client_get.backend_address_pools[0].name
        self.lb_be_id = self.lb_client_get.backend_address_pools[0].id
        self.lb_be_rules = (
            self.lb_client_get.backend_address_pools[0].load_balancing_rules)
        self.lb_be_type = self.lb_client_get.backend_address_pools[0].type
        self.lb_frontend_ip_config = (
            self.lb_client_get.frontend_ip_configurations[0])
        self.lb_public_ip_name = (
            self.lb_frontend_ip_config.public_ip_address.id.split(
                '/')[-1])
        self.lb_public_ip = self.network_client.public_ip_addresses.get(
            self.resource_group, self.lb_public_ip_name)
        self.lb_public_ip_prefix = self.lb_public_ip.ip_address
        self.lb_be_conf = (
            self.network_client.load_balancer_backend_address_pools.get(
                self.resource_group, self.lb_name, self.lb_be_name))


def terminate_vm(vm_client, resource_group, vm_name):
    """ Terminates a vm in the specified resource group """
    try:
        logging.info(f"START: Terminating instance {vm_name} "
                     f"from resource group {resource_group}")
        response = vm_client.begin_delete(resource_group, vm_name)
        response.wait()
        if response.status() == 'Succeeded':
            logging.info("End: Terminated instance successfully\n")
    except Exception as err:
        logging.warning(str(err))


def vm_scale_set_vm_info(vm_client, resource_group, scaleSetName):
    vm_name = ''
    vm_nic_name = ''
    vmScaleSetVmsLst = vm_client.list(resource_group)
    for vmScaleSetVms in vmScaleSetVmsLst:
        # Searching the VM name by appending scaleset name + _
        if scaleSetName + '_' in vmScaleSetVms.name:
            vm_name = vmScaleSetVms.name
            vm_nic = vmScaleSetVms.network_profile.network_interfaces[0]
            vm_nic_name = vm_nic.id.split('/')[-1]
    return vm_name, vm_nic_name


def run_initial_setup(api_endpoint_url="123.123.123.123/v1/api",
                      CID="ABCD1234", target_version="latest"):

    # Step1 : Check if the controller has been already initialized
    #       --> yes
    #       --> no --> run init setup (upgrading to latest controller version)
    request_method = "POST"
    data = {"action": "initial_setup", "CID": CID, "subaction": "check"}
    logging.info("Check if the initial setup has been already done or not")
    response = send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=data,
    )
    py_dict = response.json()
    if 'CID' in py_dict:
        py_dict["CID"] = "*********"
    # The initial setup has been done
    if py_dict["return"] is True:
        logging.info(
            "Initial setup for Aviatrix Controller has been already done")
        return response

    # The initial setup has not been done yet
    data = {
        "action": "initial_setup",
        "CID": CID,
        "target_version": target_version,
        "subaction": "run",
    }
    payload_with_hidden_password = dict(data)
    payload_with_hidden_password["CID"] = "********"
    logging.info(f"API endpoint url: {str(api_endpoint_url)}")
    logging.info(f"Request method is: {str(request_method)}")
    logging.info(
        f"Request payload is : "
        f"{str(json.dumps(obj=payload_with_hidden_password, indent=4))}")
    try:
        response = send_aviatrix_api(
            api_endpoint_url=api_endpoint_url,
            request_method=request_method,
            payload=data,
            retry_count=1,
            timeout=360,
        )
    except AviatrixException as ae:
        # Ignore timeout exception since it is expected
        if "Read timed out" in str(ae):
            return None
    except Exception as err:
        logging.info(f"Error occurred during initial setup: {str(err)}")
        raise
    return response


# End def run_initial_setup()

def retrieve_controller_version(version_file, container_client):
    """ Get the controller version from backup file"""
    logging.info(f"Retrieving version from file {str(version_file)}")
    s3c = container_client.get_blob_client(version_file)
    try:
        with open('/tmp/version_ctrlha.txt', 'wb') as data:
            s3c.download_blob().readinto(data)

    except Exception as err:
        logging.warning(str(err))
        logging.info("The object does not exist.")
        raise

    if not os.path.exists('/tmp/version_ctrlha.txt'):
        raise AviatrixException("Unable to open version file")

    with open("/tmp/version_ctrlha.txt") as fileh:
        buf = fileh.read()
    logging.info(f"Retrieved version {str(buf)}")

    if not buf:
        raise AviatrixException("  Version file is empty")
    logging.info("Parsing version")

    try:
        ctrl_version = ".".join((buf[12:]).split("."))
    except (KeyboardInterrupt, IndexError, ValueError) as err:
        raise AviatrixException("Could not decode version") from err
    else:
        logging.info(f"Parsed version sucessfully {str(ctrl_version)}")
        logging.warning("")
        return ctrl_version


def is_backup_file_is_recent(backup_file, container_client):
    """ Check if backup file is not older than MAXIMUM_BACKUP_AGE """
    try:
        s3c = container_client.get_blob_client(backup_file)
        try:
            file_obj = s3c.get_blob_properties()
        except Exception as err:
            logging.warning(str(err))
            return False

        age = time.time() - file_obj.last_modified.timestamp()
        if age < MAXIMUM_BACKUP_AGE:
            logging.info("Succesfully validated Backup file age\n")
            return True
        logging.warning(
            f"File age {age} is older than the maximum allowed value of "
            f"{MAXIMUM_BACKUP_AGE}")
        return False
    except Exception as err:
        logging.warning(f"  Checking backup file age failed due to {str(err)}")
        return False


def restore_ctrl_backup(creds, controller_ip, cid, storage, container, blob):
    base_url = f"https://{controller_ip}/v1/api"
    post_data = {"action": "restore_cloudx_config",
                 "cloud_type": "8",
                 "storage_name": storage,
                 "container_name": container,
                 "file_name": blob,
                 "CID": cid,
                 "arm_application_client_secret": creds['client_secret'],
                 "arm_subscription_id": creds['subscription_id'],
                 "arm_application_endpoint": creds['tenant_id'],
                 "arm_application_client_id": creds['client_id']
                 }
    payload_with_hidden_password = dict(post_data)
    payload_with_hidden_password["CID"] = "********"
    payload_with_hidden_password["arm_application_client_secret"] = "********"
    logging.info(
        f"Trying to restore backup account with data "
        f"{str(json.dumps(obj=payload_with_hidden_password, indent=4))}\n")

    try:
        response = requests.post(
            base_url, data=post_data, timeout=120, verify=False)
    except requests.Timeout:
        logging.info("Restoring backup timed out. "
                     "Please check the controller for updated config.")
        pass
    except requests.exceptions.ConnectionError as err:
        if "Remote end closed connection without response" in str(err):
            logging.info("Server closed the connection while executing "
                         "create account API. Ignoring response")
            output = {"return": True,
                      'reason': 'Warning!! Server closed the connection'}
            time.sleep(INITIAL_SETUP_DELAY)
        else:
            output = {"return": False, "reason": str(err)}
    except Exception as err:
        logging.info(f"An Error has occurred: {str(err)}")
        raise
    else:
        output = response.json()
        logging.info(output)
        return output


def main(req: func.HttpRequest, context: func.Context) -> func.HttpResponse:
    logging.basicConfig(
        format="%(asctime)s aviatrix-azure-function--- %(message)s",
        level=logging.INFO
    )
    logging.info(
        f"Version : {version.VERSION} invocation_id : {context.invocation_id}")
    req_body = req.get_json()
    headers = {"invocation_id": context.invocation_id,
               "alert_status": req_body['data']['status']}
    if not req_body['data']['status'] == 'Activated':
        logging.warning(f"Alert status type: {req_body['data']['status']}")
        return func.HttpResponse(
            "HA failover event is not triggered",
            headers=headers, status_code=501)

    event = {
        "aviatrix_api_version": "v1",
        "aviatrix_api_route": "api",
        "tenant_id": os.environ["avx_tenant_id"],
        "client_id": os.environ["avx_client_id"],
        "vault_uri": os.environ["keyvault_uri"],
        "vault_secret": os.environ["keyvault_secret"],
        "func_client_id": os.environ["func_client_id"],
        "storage_name": os.environ["storage_name"],
        "container_name": os.environ["container_name"],
        "lb_name": os.environ["lb_name"],
        "rg": os.environ["resource_group_name"]
    }

    try:
        function_handler(event)
    except Exception as err:
        logging.exception(f"Error has occurred: {str(err)}")
    else:
        logging.info("Aviatrix Controller has been initialized successfully")
        logging.info("Loading function completed !!")
        return func.HttpResponse(
            "Failover event completed successfully",
            headers=headers, status_code=200)
