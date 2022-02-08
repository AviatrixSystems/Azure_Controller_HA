import logging
import azure.functions as func
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.storage.blob import BlobServiceClient
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.network.v2021_05_01.models import SecurityRule
import os
import time
import json
import requests
import urllib3
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
    func_client_id = event["func_client_id"]
    lb_name = event["lb_name"]
    rg = event["rg"]
    wait_time = default_wait_time_for_apache_wakeup

    credentials = DefaultAzureCredential(managed_identity_client_id = func_client_id)
    subscription_client = SubscriptionClient(credentials)
    subscription = next(subscription_client.subscriptions.list())
    subscription_id = subscription.subscription_id
    resource_client = ResourceManagementClient(credentials, subscription_id)
    network_client = NetworkManagementClient(credentials, subscription_id)
    compute_client = ComputeManagementClient(credentials, subscription_id)
    
    vm_scaleset_client = compute_client.virtual_machine_scale_sets
    vm_res_client = compute_client.virtual_machines
    lb_res_client = network_client.load_balancers

    # Get Scaleset Name
    vmScaleSetName = os.environ["copilot_scaleset_name"]

    # Get Scaleset attributes
    vm_scale_set = VmScaleSet(vm_scaleset_client, rg, vmScaleSetName)

    # Get VM info in a Scaleset 
    inst_name, private_nic_name = vm_scale_set_vm_info(vm_res_client, rg, vmScaleSetName)
    logging.info(f'inst_name:{inst_name}')
    logging.info(f'private_nic_name:{private_nic_name}')
    avx_int_conf = VmNetInt(rg,network_client,private_nic_name)
    logging.info(f'avx_int_conf:{avx_int_conf}')
    old_pub_intf_id = avx_int_conf.AvxPubIntID
    logging.info(f'old_pub_intf_id:{old_pub_intf_id}')
    logging.info(avx_int_conf.AvxPubIntID)

    # Get LoadBalacer config prior to public ip removal
    lb = LbConf(lb_res_client, rg, network_client, lb_name)
    hostname = lb.lb_public_ip_prefix

    # Remove public ip Association
    avx_int_conf.rmPubIntIPAssoc()


    #vm_detail = vm_res_client.get(rg, inst_name, expand='instanceView')
    # Get VM Info
    vm = Vm(rg,vm_res_client,inst_name)
    data_disks = vm.getDisks()
    for disk in data_disks:
        if disk.create_option == 'Empty':
            disk.create_option = 'Attach'

    # Detach VM disks
    vm.detachDisks()

    # Terminate unhealthy VM
    try:
        terminate_vm(vm_res_client, rg, inst_name)
    except Exception as err:
        logging.exception(str(err))
        logging.info("There are no running VM's in a scale set ")

    # Increasing sku capacity
    logging.info("Increasing sku capacity -> 1")
    vm_scale_set.updateSku()

    #### needs to be more dynamic.. wait time for scaleset to spin up one more instance
    time.sleep(WAIT_DELAY) 

    # Get new VM info in a Scaleset 
    N_inst_name, N_private_nic_name = vm_scale_set_vm_info(vm_res_client, rg,vmScaleSetName)
    N_avx_int_conf = VmNetInt(rg,network_client,N_private_nic_name)
    N_pub_intf_conf = N_avx_int_conf.Pub_intf_conf

    # Get new VM info
    N_vm = Vm(rg,vm_res_client,N_inst_name)
    N_data_disks = N_vm.getDisks()

    # Detach new VM disks
    N_vm.detachDisks()

    # Remove new public ip Association with new instance
    N_avx_int_conf.rmPubIntIPAssoc()

    # Add old public ip Association to the new instance
    N_avx_int_conf.addPubIntIPAssoc(old_pub_intf_id)

    # Attach old VM disks
    N_vm.attachDisks(data_disks)

    # Delete the detached public ip Association to the new instance
    N_avx_int_conf.deletePubIntIP()

    # Delete new disks
    N_vm.deleteDisks(compute_client,N_data_disks)

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
                logging.info("Updated sku capacity: %s\n" % str(self.vmScaleSet.sku.capacity))
                # returns {'additional_properties': {}, 'name': 'Standard_A4_v2', 'tier': 'Standard', 'capacity': 1}
                return self.sku
        except Exception as err:
            logging.exception(str(err))

class Vm():
    def __init__(self, resource_group, vm_res_client, inst_name):
        self.instance = vm_res_client.get(resource_group, inst_name, expand='instanceView')
        self.name = inst_name
        self.resource_group = resource_group
        self.vm_res_client = vm_res_client

    def getDisks(self):        
        return self.instance.storage_profile.data_disks

    def detachDisks(self):
        try:
            self.instance.storage_profile.data_disks = []
            logging.info("START: Detach data disks from vm: %s" % str(self.name))
            response = self.vm_res_client.begin_create_or_update(self.resource_group,self.name,self.instance)
            response.wait()
            if response.status() == 'Succeeded': 
                logging.info("END: Detach data disks from vm: %s" % str(self.name))
        except Exception as err:
            logging.exception(str(err))

    def attachDisks(self,disks):
        try:
            self.instance.storage_profile.data_disks = disks
            logging.info("START: Attach data disks from vm: %s" % str(self.name))
            response = self.vm_res_client.begin_create_or_update(self.resource_group,self.name,self.instance)
            response.wait()
            if response.status() == 'Succeeded': 
                logging.info("END: Attach data disks from vm: %s" % str(self.name))
        except Exception as err:
            logging.exception(str(err))

    def deleteDisks(self,compute_client,disks):
        disk_handle_list = []
        try:
            for disk in disks:
                async_disk_delete = compute_client.disks.begin_delete(self.resource_group, disk.name)
                disk_handle_list.append(async_disk_delete)
            logging.info("START: Delete queued disks")
            for async_disk_delete in disk_handle_list:
                async_disk_delete.wait()
            logging.info("END: Delete queued disks")
        except Exception as err:
            logging.exception(str(err))

#### As a prevalidation :
# 1. Make sure eip is asscosiated with controller
# 2. Make sure instance exists if N?A start from updating capacity -- Need to think of getting public ip info
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
            logging.info("START: Dissociate %s : %s from %s" % (self.AvxPubIntName,self.AvxPubIntIP, self.AvxPrivIntIP))
            response = self.network_client.network_interfaces.begin_create_or_update( self.resource_group, self.vm_intf_name, inf_conf_model)
            response.wait()
            if response.status() == 'Succeeded':        
                logging.info("End: Dissociate completed successfully\n")
        except Exception as err:
            logging.exception(str(err))

    def addPubIntIPAssoc(self,old_public_ip_name):
        """ Associates old public IP to the new vm """
        params = {'id' : old_public_ip_name}
        inf_conf_model = self.Pri_intf_conf
        inf_conf_model.ip_configurations[0].public_ip_address = params
        try:
            logging.info("START: Associate %s with %s" % (old_public_ip_name.split('/')[-1], self.AvxPrivIntIP))
            response = self.network_client.network_interfaces.begin_create_or_update( self.resource_group, self.vm_intf_name, inf_conf_model)
            response.wait()
            if response.status() == 'Succeeded':
                logging.info("End: Associate completed successfully\n")
        except Exception as err:
            logging.exception(str(err))

    def deletePubIntIP(self):
        """ Deletes the public IP """
        try:
            logging.info("START: Delete newly created %s : %s from %s" % (self.AvxPubIntName,self.AvxPubIntIP,self.resource_group))
            response = self.network_client.public_ip_addresses.begin_delete( self.resource_group, self.AvxPubIntName)
            response.wait()
            if response.status() == 'Succeeded':   
                logging.info("End: Delete public ip successfully\n")
        except Exception as err:
            logging.exception(str(err))

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
        logging.info("START: Terminate instance %s from resource group %s" % (vm_name,resource_group))
        response = vm_client.begin_delete(resource_group, vm_name)
        response.wait()
        if response.status() == 'Succeeded':
            logging.info("End: Terminate instance successfully\n")
    except Exception as err:
        logging.exception(str(err))

def vm_scale_set_vm_info(vm_client,resource_group, scaleSetName):
    vm_name = ''
    vm_nic_name = ''
    vmScaleSetVmsLst = vm_client.list(resource_group)
    for vmScaleSetVms in vmScaleSetVmsLst:
        #### Searching the VM name by appending scaleset name + _
        if scaleSetName + '_' in vmScaleSetVms.name:
            vm_name = vmScaleSetVms.name
            vm_nic_name = vmScaleSetVms.network_profile.network_interfaces[0].id.split('/')[-1]
    return vm_name,vm_nic_name


def main(req: func.HttpRequest, context: func.Context) -> func.HttpResponse:
    logging.basicConfig(
        format="%(asctime)s aviatrix-azure-function--- %(message)s", level=logging.INFO
    )
    logging.info(f"invocation_id : {context.invocation_id}")
    req_body = req.get_json()
    headers = {"invocation_id": context.invocation_id, "alert_status": req_body['data']['status']}
    if not req_body['data']['status'] == 'Activated':
        logging.warning(f"Alert status type: {req_body['data']['status']}")
        return func.HttpResponse(
                "HA failover event is not triggered",
                headers=headers, status_code=501)

    event = {
        "func_client_id" : os.environ["func_client_id"],
        "lb_name" : req_body['data']['context']['resourceName'],
        "rg" : req_body['data']['context']['resourceGroupName']
    }

    try:
        function_handler(event)
    except Exception as e:
        logging.exception("")
    else:
        logging.info("Aviatrix Copilot has been initialized successfully")
        logging.info("Loading function completed !!")
        return func.HttpResponse(
                "Failover event completed successfully",
                headers=headers, status_code=200)