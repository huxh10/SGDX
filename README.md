# SGRS and SGDX: Preserve Privacy at IXPs

## iSDX Installation: Vagrant Setup

### Prerequisite

To get started install these softwares on your ```host``` machine:

Install Vagrant, VirtualBox, Git, X Server and SSH capable terminal

### Basics

* Clone the ```iSDX``` repository from Github:
```bash 
$ git clone https://github.com/huxh10/iSDX.git
```

* Now run the vagrant up command. This will read the Vagrantfile from the current directory and provision the VM accordingly:
```bash
$ vagrant up
```

The provisioning scripts will install all the required software (and their dependencies) to run the SDX demo. Specifically it will install:
* [Ryu](http://osrg.github.io/ryu/)
* [Quagga](http://www.nongnu.org/quagga/)
* [Mininet](http://mininet.org/)
* [Exabgp](https://github.com/Exa-Networks/exabgp)

## SGX Installation

Install and setup Intel SGX [driver](https://github.com/01org/linux-sgx-driver) and [SDK](https://github.com/01org/linux-sgx).

To run the system in hardware mode, CPU should be SkyLake or later version.

## Directory Structure

The top level directories are:
* pure iSDX source code:
    * [`xrs`](https://github.com/huxh10/iSDX/tree/master/xrs) - BGP Relay component (route server)
    * [`pctrl-isdx`](https://github.com/huxh10/iSDX/tree/master/pctrl-isdx) - iSDX original Participant Controller component
    * [`arproxy`](https://github.com/huxh10/iSDX/tree/master/arproxy) - ARP Relay component
    * [`xctrl`](https://github.com/huxh10/iSDX/tree/master/xctrl) - Central Controller component (runs at startup to load initial switch rules)
    * [`flanc`](https://github.com/huxh10/iSDX/tree/master/flanc) - Fabric Manager component (a.k.a. 'refmon')
    * [`util`](https://github.com/huxh10/iSDX/tree/master/util) - Common code
    * [`test`](https://github.com/huxh10/iSDX/tree/master/test) - Test Framework and example tests
    * [`visualization`](https://github.com/huxh10/iSDX/tree/master/visualization) - Tools for visualizing iSDX flows
    * [`setup`](https://github.com/huxh10/iSDX/tree/master/setup) - Scripts run from the Vagrantfile when the VM is created
    * [`bin`](https://github.com/huxh10/iSDX/tree/master/bin) - Utility scripts
* privacy-preserving source code:
    * [`sxrs`](https://github.com/huxh10/iSDX/tree/master/sxrs) - SGRS
    * [`pprs`](https://github.com/huxh10/iSDX/tree/master/pprs) - SIXPACK
    * [`aby`](https://github.com/huxh10/iSDX/tree/master/aby) - ABY library and core functions for SIXPACK
    * [`xbgp`](https://github.com/huxh10/iSDX/tree/master/xbgp) - BGP update generator
    * [`pctrl-sgdx`](https://github.com/huxh10/iSDX/tree/master/pctrl-sgdx) - Modified iSDX Participant Controller component for SGDX
    * [`plot`](https://github.com/huxh10/iSDX/tree/master/plot) - Scripts to plot the results
* test datasets
    * [`examples`](https://github.com/huxh10/iSDX/tree/master/examples) - Working examples with datasets and related generator

## Usage
Run the different setups provided in the [`examples`](https://github.com/huxh10/iSDX/tree/master/examples/test-ms) directory.

To try original iSDX, check out the [`test-ms`](https://github.com/huxh10/iSDX/tree/master/examples/test-ms) example for a simple case with three IXP participants.

To run the comparison experiments of SGRS and SIXPACK, check out the [`test-rs`](https://github.com/huxh10/iSDX/tree/master/examples/test-rs) example for generating datasets. Run scripts in [`sxrs`](https://github.com/huxh10/iSDX/tree/master/sxrs) and [`pprs`](https://github.com/huxh10/iSDX/tree/master/pprs).

To run the comparison experiments of SGDX and iSDX, check out the [`test-sdx`](https://github.com/huxh10/iSDX/tree/master/examples/test-sdx) example for generating datasets. Run scripts in [`pctrl-sgdx`](https://github.com/huxh10/iSDX/tree/master/pctrl-sgdx) and [`pctrl-isdx`](https://github.com/huxh10/iSDX/tree/master/pctrl-isdx).
