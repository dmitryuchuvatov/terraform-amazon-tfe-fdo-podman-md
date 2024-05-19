# tfe_fdo_on_podman_in_mounted_disk_mode.py

from diagrams import Cluster, Diagram
from diagrams.aws.general import Client
from diagrams.aws.network import Route53
from diagrams.aws.compute import EC2

with Diagram("TFE FDO on Podman in Mounted Disk mode", show=False, direction="TB"):
    
    client = Client("Client")
    
    with Cluster("AWS"):
        dns = Route53("DNS")
        with Cluster("VPC"):
            with Cluster("Public Subnet"):
                tfe_instance = EC2("RHEL instance")

    client >> dns
    dns >> tfe_instance