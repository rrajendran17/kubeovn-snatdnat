

# Kubeovn SNAT DNAT Introduction
NAT enables external connectivity or inbound access: SNAT (Source NAT) allows VMs (or pods) inside a private overlay network / VPC to access external networks (e.g. internet) by translating their internal source IP to a public (or external-network-shared) IP. DNAT (Destination NAT) allows external hosts to reach internal VMs/pods by mapping a public IP / port to an internal private IP / port (e.g. to SSH into an internal VM). 

Flexible networking for VPCs / overlay networks: Using NAT (SNAT / DNAT) with Kube-OVN means you can build isolated private subnets / VPCs and still allow controlled egress (outbound) or ingress (inbound) traffic. This is especially relevant for VM workloads managed by Harvester, where VMs may need internet access or to expose services externally.

Kube-OVN supports NAT via Kubernetes custom resources (CRDs), not just IP-tables directly. For example, resources like OvnEip, OvnSnatRule, OvnDnatRule (or their iptables-based equivalents) are used to define NAT behavior declaratively. 
In the context of Harvester, the VM orchestration (compute, storage, VM lifecycle) is handled by Harvester; networking — including routing, NAT, VPC/subnets — is handled by Kube-OVN. This separation allows for more scalable, flexible and clean networking. 

## External connectivity from VMs on custom VPCs using kubeovn as Secondary CNI
Currently VMs will be able to reach external hosts only when attached to subnets created on default VPC (ovn-cluster) with natOutgoing as true.

With the introduction of using kubeovn as secondary CNI (from v1.15.x kubeovn version kubeovn/kube-ovn#5360), VMs must be able to connect with external hosts on subnets created on any custom VPCs.This task is a place holder to verify VMs external connectivity on subnets created on custom VPC using VPC NAT Gateway and kubeovn acting as secondary CNI.And fix any issues related to this.

- Enable kubeovn as secondary CNI
```
   containers:
      - args:
        - /kube-ovn/start-controller.sh
        - --non-primary-cni-mode=true
```
- Create a network attachment definition (tenant or internal network)
  
```
apiVersion: k8s.cni.cncf.io/v1
kind: NetworkAttachmentDefinition
metadata:
  annotations:
    network.harvesterhci.io/route: '{"mode":"auto","serverIPAddr":"","cidr":"","gateway":""}'
  creationTimestamp: "2025-11-06T23:23:43Z"
  finalizers:
  - wrangler.cattle.io/harvester-network-nad-controller
  - wrangler.cattle.io/harvester-network-manager-nad-controller
  generation: 1
  labels:
    network.harvesterhci.io/ready: "true"
    network.harvesterhci.io/type: OverlayNetwork
  name: vswitchinternal
  namespace: default
  resourceVersion: "3149972"
  uid: e99a21c9-8ad7-48de-97a0-15b39ff01b1c
spec:
  config: '{"cniVersion":"0.3.1","name":"vswitchinternal","type":"kube-ovn","server_socket":
    "/run/openvswitch/kube-ovn-daemon.sock", "provider": "vswitchinternal.default.ovn"}'
```
- Create a network attachment definition (external network)

```
kubectl get net-attach-def vswitchexternal1 -o yaml
apiVersion: k8s.cni.cncf.io/v1
kind: NetworkAttachmentDefinition
metadata:
  annotations:
    network.harvesterhci.io/route: '{"mode":"auto","serverIPAddr":"","cidr":"","gateway":""}'
  creationTimestamp: "2025-11-09T17:52:11Z"
  finalizers:
  - wrangler.cattle.io/harvester-network-manager-nad-controller
  generation: 1
  labels:
    network.harvesterhci.io/ready: "true"
    network.harvesterhci.io/type: OverlayNetwork
  name: vswitchexternal1
  namespace: kube-system
  resourceVersion: "5965195"
  uid: 695ac130-36c1-4a92-b25d-3e588e921bb4
spec:
  config: '{"cniVersion":"0.3.1","name":"vswitchexternal1","master": "eno50","type":"kube-ovn","server_socket":
    "/run/openvswitch/kube-ovn-daemon.sock", "provider": "vswitchexternal1.kube-system.ovn"}'
```
- create a subnet using the internal or tenant network in custom vpc named "commonvpc"

```
apiVersion: kubeovn.io/v1
kind: Subnet
metadata:
  annotations:
  creationTimestamp: "2025-11-06T23:23:54Z"
  finalizers:
  - kubeovn.io/kube-ovn-controller
  generation: 3
  name: subnetinternal
  resourceVersion: "5955405"
  uid: 6384729b-83d3-40f0-b4f8-882c4abc0b6f
spec:
  cidrBlock: 172.20.10.0/24
  default: false
  enableLb: true
  excludeIps:
  - 172.20.10.1
  gateway: 172.20.10.1
  gatewayNode: ""
  natOutgoing: true
  private: false
  protocol: IPv4
  provider: vswitchinternal.default.ovn
  vpc: commonvpc
```

- Create a subnet using the external network

```
apiVersion: kubeovn.io/v1
kind: Subnet
metadata:
  annotations:
  creationTimestamp: "2025-11-09T17:52:22Z"
  finalizers:
  - kubeovn.io/kube-ovn-controller
  generation: 3
  name: subnetexternal
  resourceVersion: "5978195"
  uid: a244db8c-2ed1-4beb-9095-a9098b556330
spec:
  cidrBlock: 10.115.8.0/21
  default: false
  enableLb: true
  excludeIps:
  - 10.115.15.254
  gateway: 10.115.15.254
  gatewayNode: ""
  gatewayType: distributed
  natOutgoing: true
  private: false
  protocol: IPv4
  provider: vswitchexternal1.kube-system.ovn
  vpc: ovn-cluster
```

- Underlay Physical network

```
ip addr show rrrr-br.2012
220: rrrr-br.2012@rrrr-br: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether ea:50:43:b0:fd:44 brd ff:ff:ff:ff:ff:ff
    inet 10.115.14.246/21 brd 10.115.15.255 scope global dynamic noprefixroute rrrr-br.2012
       valid_lft 371sec preferred_lft 371sec
    inet6 fe80::baee:4fdf:f127:583e/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
hp-65:~/vpcgwtest # bridge vlan show
port              vlan-id  
mgmt-br           1 PVID Egress Untagged
                  2021
mgmt-bo           1 PVID Egress Untagged
                  2021
rrrr-bo           1 PVID Egress Untagged
                  2012
                  2021
rrrr-br           1 PVID Egress Untagged
                  2012

ip route show

10.115.8.0/21 dev rrrr-br.2012 proto kernel scope link src 10.115.14.246 metric 401

ping 8.8.8.8 -I rrrr-br.2012
PING 8.8.8.8 (8.8.8.8) from 10.115.14.246 rrrr-br.2012: 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=116 time=13.8 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=116 time=13.8 ms
```

- Enable the vpc nat gateway config

```
kubectl get configmap -n kube-system ovn-vpc-nat-config -o yaml
apiVersion: v1
data:
  image: docker.io/kubeovn/vpc-nat-gateway:v1.15.0
kind: ConfigMap
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"v1","data":{"image":"docker.io/kubeovn/vpc-nat-gateway:v1.15.0"},"kind":"ConfigMap","metadata":{"annotations":{},"name":"ovn-vpc-nat-config","namespace":"kube-system"}}
  creationTimestamp: "2025-11-07T17:51:35Z"
  name: ovn-vpc-nat-config
  namespace: kube-system
  resourceVersion: "3926039"
  uid: faf6fc27-7cf5-4782-b939-0e78c76cf281

kubectl get configmap -n kube-system ovn-vpc-nat-gw-config -o yaml
apiVersion: v1
data:
  enable-vpc-nat-gw: "true"
kind: ConfigMap
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"v1","data":{"enable-vpc-nat-gw":"true"},"kind":"ConfigMap","metadata":{"annotations":{},"name":"ovn-vpc-nat-gw-config","namespace":"kube-system"}}
  creationTimestamp: "2025-11-07T17:51:35Z"
  name: ovn-vpc-nat-gw-config
  namespace: kube-system
  resourceVersion: "3926040"
  uid: 2ce03b0d-f711-43fb-9aea-953e34229ab3
```

- create the vpc nat gateway config

```
kind: VpcNatGateway
apiVersion: kubeovn.io/v1
metadata:
  annotations:
        k8s.v1.cni.cncf.io/networks: default/vswitchinternal
  name: gw1
spec:
  vpc: commonvpc
  subnet: subnetinternal
  lanIp: 172.20.10.254
  externalSubnets:
    - subnetexternal
```

- Verify if a new vpcnatgw statefulset and a pod created

```
kubectl get statefulset -n kube-system vpc-nat-gw-gw1 -o yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  creationTimestamp: "2025-11-10T03:05:02Z"
  generation: 1
  labels:
    app: vpc-nat-gw-gw1
    ovn.kubernetes.io/vpc-nat-gw: "true"
  name: vpc-nat-gw-gw1
  namespace: kube-system
  resourceVersion: "6359505"
  uid: 6ec54754-d483-4c6b-988d-616721664fdf
spec:
  persistentVolumeClaimRetentionPolicy:
    whenDeleted: Retain
    whenScaled: Retain
  podManagementPolicy: OrderedReady
  replicas: 1
  revisionHistoryLimit: 10
  selector:
    matchLabels:
      app: vpc-nat-gw-gw1
      ovn.kubernetes.io/vpc-nat-gw: "true"
  serviceName: ""
  template:
    metadata:
      annotations:
        k8s.v1.cni.cncf.io/networks: default/vswitchinternal, kube-system/vswitchexternal1
        ovn.kubernetes.io/ip_address: 172.20.10.254
        ovn.kubernetes.io/logical_switch: subnetinternal
        ovn.kubernetes.io/vpc_nat_gw: gw1
        vswitchexternal1.kube-system.ovn.kubernetes.io/routes: '[{"dst":"0.0.0.0/0","gw":"10.115.15.254"}]'
        vswitchinternal.default.ovn.kubernetes.io/ip_address: 172.20.10.254
        vswitchinternal.default.ovn.kubernetes.io/logical_switch: subnetinternal
        vswitchinternal.default.ovn.kubernetes.io/routes: '[{"dst":"10.96.0.0/12","gw":"172.20.10.1"},{"dst":"172.20.10.0/24","gw":"172.20.10.1"}]'
        vswitchinternal.default.ovn.kubernetes.io/vpc_nat_gw: gw1
      creationTimestamp: null
      labels:
        app: vpc-nat-gw-gw1
        ovn.kubernetes.io/vpc-nat-gw: "true"
    spec:
      affinity: {}
      containers:
      - command:
        - sleep
        - infinity
        env:
        - name: GATEWAY_V4
          value: 10.115.15.254
        - name: GATEWAY_V6
        image: docker.io/kubeovn/vpc-nat-gateway:v1.15.0
        imagePullPolicy: IfNotPresent
        name: vpc-nat-gw
        resources: {}
        securityContext:
          allowPrivilegeEscalation: true
          privileged: true
        terminationMessagePath: /dev/termination-log
        terminationMessagePolicy: File
      dnsPolicy: ClusterFirst
      restartPolicy: Always
      schedulerName: default-scheduler
      securityContext: {}
      terminationGracePeriodSeconds: 0
  updateStrategy:
    type: RollingUpdate
status:
  availableReplicas: 1
  collisionCount: 0
  currentReplicas: 1
  currentRevision: vpc-nat-gw-gw1-5fd8d64b77
  observedGeneration: 1
  readyReplicas: 1
  replicas: 1
  updateRevision: vpc-nat-gw-gw1-5fd8d64b77
  updatedReplicas: 1

```

```
kubectl describe pod vpc-nat-gw-gw1-0 -n kube-system
Name:             vpc-nat-gw-gw1-0
Namespace:        kube-system
Priority:         0
Service Account:  default
Node:             hp-65/10.115.252.137
Start Time:       Mon, 10 Nov 2025 03:05:02 +0000
Labels:           app=vpc-nat-gw-gw1
                  apps.kubernetes.io/pod-index=0
                  controller-revision-hash=vpc-nat-gw-gw1-5fd8d64b77
                  ovn.kubernetes.io/vpc-nat-gw=true
                  statefulset.kubernetes.io/pod-name=vpc-nat-gw-gw1-0
Annotations:      cni.projectcalico.org/containerID: 59fa82decad3b8814c83141c01426e9aa6cdcc1bc11996a535a7b99b7ac324f7
                  cni.projectcalico.org/podIP: 10.52.0.189/32
                  cni.projectcalico.org/podIPs: 10.52.0.189/32
                  k8s.v1.cni.cncf.io/network-status:
                    [{
                        "name": "k8s-pod-network",
                        "ips": [
                            "10.52.0.189"
                        ],
                        "default": true,
                        "dns": {}
                    },{
                        "name": "default/vswitchinternal",
                        "interface": "net1",
                        "ips": [
                            "172.20.10.254"
                        ],
                        "mac": "1e:2d:fc:14:ef:51",
                        "dns": {}
                    },{
                        "name": "kube-system/vswitchexternal1",
                        "interface": "net2",
                        "ips": [
                            "10.115.8.3"
                        ],
                        "mac": "aa:5a:19:2a:26:6f",
                        "dns": {},
                        "gateway": [
                            "10.115.15.254"
                        ]
                    }]
                  k8s.v1.cni.cncf.io/networks: default/vswitchinternal, kube-system/vswitchexternal1
                  ovn.kubernetes.io/ip_address: 172.20.10.254
                  ovn.kubernetes.io/logical_switch: subnetinternal
                  ovn.kubernetes.io/vpc_nat_gw: gw1
                  ovn.kubernetes.io/vpc_nat_gw_init: true
                  vswitch1.default.ovn.kubernetes.io/vpc_cidrs: ["172.20.10.0/24"]
                  vswitchexternal1.kube-system.ovn.kubernetes.io/allocated: true
                  vswitchexternal1.kube-system.ovn.kubernetes.io/cidr: 10.115.8.0/21
                  vswitchexternal1.kube-system.ovn.kubernetes.io/gateway: 10.115.15.254
                  vswitchexternal1.kube-system.ovn.kubernetes.io/ip_address: 10.115.8.3
                  vswitchexternal1.kube-system.ovn.kubernetes.io/logical_router: ovn-cluster
                  vswitchexternal1.kube-system.ovn.kubernetes.io/logical_switch: subnetexternal
                  vswitchexternal1.kube-system.ovn.kubernetes.io/mac_address: aa:5a:19:2a:26:6f
                  vswitchexternal1.kube-system.ovn.kubernetes.io/pod_nic_type: veth-pair
                  vswitchexternal1.kube-system.ovn.kubernetes.io/routed: true
                  vswitchexternal1.kube-system.ovn.kubernetes.io/routes: [{"dst":"0.0.0.0/0","gw":"10.115.15.254"}]
                  vswitchinternal.default.ovn.kubernetes.io/allocated: true
                  vswitchinternal.default.ovn.kubernetes.io/cidr: 172.20.10.0/24
                  vswitchinternal.default.ovn.kubernetes.io/gateway: 172.20.10.1
                  vswitchinternal.default.ovn.kubernetes.io/ip_address: 172.20.10.254
                  vswitchinternal.default.ovn.kubernetes.io/logical_router: commonvpc
                  vswitchinternal.default.ovn.kubernetes.io/logical_switch: subnetinternal
                  vswitchinternal.default.ovn.kubernetes.io/mac_address: 1e:2d:fc:14:ef:51
                  vswitchinternal.default.ovn.kubernetes.io/pod_nic_type: veth-pair
                  vswitchinternal.default.ovn.kubernetes.io/routed: true
                  vswitchinternal.default.ovn.kubernetes.io/routes: [{"dst":"10.96.0.0/12","gw":"172.20.10.1"},{"dst":"172.20.10.0/24","gw":"172.20.10.1"}]
                  vswitchinternal.default.ovn.kubernetes.io/vpc_cidrs: ["172.20.10.0/24"]
                  vswitchinternal.default.ovn.kubernetes.io/vpc_nat_gw: gw1
Status:           Running
IP:               10.52.0.189
IPs:
  IP:           10.52.0.189
Controlled By:  StatefulSet/vpc-nat-gw-gw1
Containers:
  vpc-nat-gw:
    Container ID:  containerd://e5e1f18abe9b6395e2c6b95f4de235924f1bb12bf240079cf767d8e82f89b961
    Image:         docker.io/kubeovn/vpc-nat-gateway:v1.15.0
    Image ID:      docker.io/kubeovn/vpc-nat-gateway@sha256:2ca4df9584b36eb973d609fbc76c705bf5d6ff22ea242b4c8275ceca59a7ae5b
    Port:          <none>
    Host Port:     <none>
    Command:
      sleep
      infinity
    State:          Running
      Started:      Mon, 10 Nov 2025 03:05:15 +0000
    Ready:          True
    Restart Count:  0
    Environment:
      GATEWAY_V4:  10.115.15.254
      GATEWAY_V6:  
    Mounts:
      /var/run/secrets/kubernetes.io/serviceaccount from kube-api-access-ls5hs (ro)
Conditions:
  Type                        Status
  PodReadyToStartContainers   True 
  Initialized                 True 
  Ready                       True 
  ContainersReady             True 
  PodScheduled                True 
Volumes:
  kube-api-access-ls5hs:
    Type:                    Projected (a volume that contains injected data from multiple sources)
    TokenExpirationSeconds:  3607
    ConfigMapName:           kube-root-ca.crt
    Optional:                false
    DownwardAPI:             true
QoS Class:                   BestEffort
Node-Selectors:              <none>
Tolerations:                 node.kubernetes.io/not-ready:NoExecute op=Exists for 300s
                             node.kubernetes.io/unreachable:NoExecute op=Exists for 300s
Events:                      <none>

```

- Create EIP and SNAT resource

```
kubectl get eip my-eip -o yaml
apiVersion: kubeovn.io/v1
kind: IptablesEIP
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"kubeovn.io/v1","kind":"IptablesEIP","metadata":{"annotations":{},"name":"my-eip"},"spec":{"externalSubnet":"vswitchexternal1","natGwDp":"gw1"}}
  creationTimestamp: "2025-11-10T03:06:20Z"
  finalizers:
  - kubeovn.io/kube-ovn-controller
  generation: 2
  labels:
    ovn.kubernetes.io/eip_v4_ip: 10.115.8.2
    ovn.kubernetes.io/subnet: vswitchexternal1
    ovn.kubernetes.io/vpc-nat-gw-name: gw1
  name: my-eip
  resourceVersion: "6360362"
  uid: 16962458-142d-4200-99ca-dfa70ee8cad6
spec:
  externalSubnet: vswitchexternal1
  macAddress: be:8b:0e:bf:85:16
  natGwDp: gw1
  qosPolicy: ""
  v4ip: 10.115.8.2
  v6ip: ""
status:
  ip: 10.115.8.2
  nat: snat
  qosPolicy: ""
  ready: true
  redo: ""
```

```
kubectl get snat my-snat -o yaml
apiVersion: kubeovn.io/v1
kind: IptablesSnatRule
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"kubeovn.io/v1","kind":"IptablesSnatRule","metadata":{"annotations":{},"name":"my-snat"},"spec":{"eip":"my-eip","internalCIDR":"172.20.10.0/24"}}
    ovn.kubernetes.io/vpc_eip: my-eip
  creationTimestamp: "2025-11-10T03:06:25Z"
  finalizers:
  - kubeovn.io/kube-ovn-controller
  generation: 1
  labels:
    ovn.kubernetes.io/eip_v4_ip: 10.115.8.2
    ovn.kubernetes.io/vpc-nat-gw-name: gw1
  name: my-snat
  resourceVersion: "6360361"
  uid: 88155c5f-6cef-4494-bb4b-51d130d15cd4
spec:
  eip: my-eip
  internalCIDR: 172.20.10.0/24
status:
  internalCIDR: 172.20.10.0/24
  natGwDp: gw1
  ready: true
  redo: ""
  v4ip: 10.115.8.2
  v6ip: ""
```

```
kubectl get eip
NAME     IP           MAC                 NAT    NATGWDP   READY
my-eip   10.115.8.2   be:8b:0e:bf:85:16   snat   gw1       true
hp-65:~/vpcgwtest # kubectl get snat
NAME      EIP      V4IP         V6IP   INTERNALCIDR     NATGWDP   READY
my-snat   my-eip   10.115.8.2          172.20.10.0/24   gw1       true

```
- Check the vpc nat gw pod for interfaces, route and iptable rules

```
ubectl exec -it vpc-nat-gw-gw1-0 -n kube-system -- /bin/bash
vpc-nat-gw-gw1-0:/kube-ovn# ip addr show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0@if305: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UP group default qlen 1000
    link/ether 82:41:cc:0d:bc:36 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.52.0.189/32 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::8041:ccff:fe0d:bc36/64 scope link 
       valid_lft forever preferred_lft forever
306: net1@if307: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1400 qdisc noqueue state UP group default 
    link/ether 1e:2d:fc:14:ef:51 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.20.10.254/24 brd 172.20.10.255 scope global net1
       valid_lft forever preferred_lft forever
    inet6 fe80::1c2d:fcff:fe14:ef51/64 scope link 
       valid_lft forever preferred_lft forever
308: net2@if309: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1400 qdisc noqueue state UP group default 
    link/ether aa:5a:19:2a:26:6f brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.115.8.3/21 brd 10.115.15.255 scope global net2
       valid_lft forever preferred_lft forever
    inet 10.115.8.2/21 scope global secondary net2
       valid_lft forever preferred_lft forever
    inet6 fe80::a85a:19ff:fe2a:266f/64 scope link 
       valid_lft forever preferred_lft forever
vpc-nat-gw-gw1-0:/kube-ovn# ip route show
default via 10.115.15.254 dev net2 
10.96.0.0/12 via 172.20.10.1 dev net1 
10.115.8.0/21 dev net2 proto kernel scope link src 10.115.8.3 
169.254.1.1 dev eth0 scope link 
172.20.10.0/24 via 172.20.10.1 dev net1 
vpc-nat-gw-gw1-0:/kube-ovn# ping -I 10.115.8.3 8.8.8.8
PING 8.8.8.8 (8.8.8.8) from 10.115.8.3 : 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=4 ttl=115 time=15.5 ms
```

- Create a provider network with vlan id 2012 and physical interface and a vlan network attached to the provider network.
```
piVersion: kubeovn.io/v1
kind: ProviderNetwork
metadata:
  name: pn1
spec:
  defaultInterface: eno50

```

```
apiVersion: kubeovn.io/v1
kind: Vlan
metadata:
  name: vlan2012
spec:
  id: 2012
  provider: pn1
```

-  Edit subnet subnetexternal to use vlan as vlan2012 (this will attach this subnet to the provider network underlay)

```
apiVersion: kubeovn.io/v1
kind: Subnet
metadata:
  annotations:
  creationTimestamp: "2025-11-09T17:52:22Z"
  finalizers:
  - kubeovn.io/kube-ovn-controller
  generation: 3
  name: subnetexternal
  resourceVersion: "5978195"
  uid: a244db8c-2ed1-4beb-9095-a9098b556330
spec:
  cidrBlock: 10.115.8.0/21
  default: false
  enableLb: true
  excludeIps:
  - 10.115.15.254
  gateway: 10.115.15.254
  gatewayNode: ""
  gatewayType: distributed
  natOutgoing: true
  private: false
  protocol: IPv4
  provider: vswitchexternal1.kube-system.ovn
  vpc: ovn-cluster
  vlan: vlan2012
```

- Verify provider network bridge and external subnet attached on the ovs

```
kubectl exec -it ovs-ovn-q92zk -n kube-system -- /bin/bash
Defaulted container "openvswitch" out of: openvswitch, hostpath-init (init)
nobody@hp-65:/kube-ovn$ ovs-vsctl show
54ef5649-9fe6-4944-865b-30a591c95121
    Bridge br-int
        fail_mode: secure
        datapath_type: system
        Port br-int
            Interface br-int
                type: internal
        Port "9bb3a_37a8eec_h"
            Interface "9bb3a_37a8eec_h"
        Port "59fa82de_net2_h"
            Interface "59fa82de_net2_h"
        Port mirror0
            Interface mirror0
                type: internal
        Port ovn0
            Interface ovn0
                type: internal
        Port "59fa82de_net1_h"
            Interface "59fa82de_net1_h"
        Port "47e27_37a8eec_h"
            Interface "47e27_37a8eec_h"
        Port patch-br-int-to-localnet.subnetexternal
            Interface patch-br-int-to-localnet.subnetexternal
                type: patch
                options: {peer=patch-localnet.subnetexternal-to-br-int}
    Bridge br-pn1
        Port rrrr-br.2012
            trunks: [0, 2012]
            Interface rrrr-br.2012
        Port br-pn1
            Interface br-pn1
                type: internal
        Port patch-localnet.subnetexternal-to-br-int
            Interface patch-localnet.subnetexternal-to-br-int
                type: patch
                options: {peer=patch-br-int-to-localnet.subnetexternal}
    ovs_version: "3.5.3"

```

- check the SNAT filter iptable rule created inside the vpc nat gw pod

```
vpc-nat-gw-gw1-0:/kube-ovn# iptables-legacy-save -t nat
# Generated by iptables-save v1.8.11 on Mon Nov 10 18:45:06 2025
*nat
:PREROUTING ACCEPT [57805:4855620]
:INPUT ACCEPT [2:168]
:OUTPUT ACCEPT [113:8229]
:POSTROUTING ACCEPT [113:8229]
:DNAT_FILTER - [0:0]
:EXCLUSIVE_DNAT - [0:0]
:EXCLUSIVE_SNAT - [0:0]
:SHARED_DNAT - [0:0]
:SHARED_SNAT - [0:0]
:SNAT_FILTER - [0:0]
-A PREROUTING -j DNAT_FILTER
-A POSTROUTING -j SNAT_FILTER
-A DNAT_FILTER -j EXCLUSIVE_DNAT
-A DNAT_FILTER -j SHARED_DNAT
-A SHARED_SNAT -s 172.20.10.0/24 -o net2 -j SNAT --to-source 10.115.8.2 --random-fully
-A SNAT_FILTER -j EXCLUSIVE_SNAT
-A SNAT_FILTER -j SHARED_SNAT
COMMIT
# Completed on Mon Nov 10 18:45:06 2025
```
