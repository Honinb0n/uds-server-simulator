# uds-server-simulator
A configurable CAN UDS simulator.

Author: Honinbon

## Intro
This project is used to simulate the UDS server in the ECU, and can be configured into different ECU information through configuration files. This project welcomes all security researchers, security testers and bros interested in learning about ISO-14229.

## Preparation
If you have only an ubuntu without a can-hardware, you need to enable a virtual can interface.
```sh
sudo ip link add dev can0 type vcan

sudo ip link set can0 up
```

## Build
Compile it with `make` after `git clone` the repository.

```sh
git clone https://github.com/Honinb0n/uds-server-simulator.git

cd ./uds-server-simulator

make
```

## Configration file
The file `config.json` defines every ECU's information which needs to be initialized.

The `CURRENT_ECU` specifies which ECU the server should simulate.

You can also add custom ECU information with the following fields:

* **Mandatory**
    * `func_req_id`: can be set to "0x7DF", or an empty string.
    * `phy_req_id`: e.g. "0x703"
    * `phy_resp_id`: e.g. "0x7A3"    

* **Optional** 
    * format: {"DID": "DATA", ...}   
        * `DID_No_Security`: These DIDs can be read and written without authentication.
        * `DID_Security_03`: These DIDs can be read without authentication but require 2703 authentication for writing.
        * `DID_Security_19`: These DIDs can be read without authentication but require 2719 authentication for writing.   
        * `DID_Security_21`: These DIDs require 2721 authentication for reading and writing.
    * format: [DID1, DID2, ...] 
        * `DID_IO_Control`: The IO operation corresponding to the DID must be controlled with 27 authentication.

Examples:
```json
"GW": {
        "func_req_id": "",
        "phy_req_id": "0x703",
        "phy_resp_id": "0x7A3",
        "DID_No_Security": {
            "0xF18B": "2023.06.23"
        },
        "DID_Security_03": {
            "0xF180": "boot v1.0.1", 
            "0xF187": "GW v1.1.1"
        },
        "DID_Security_19": {
            "0xF190": "LUAU2AUB3GE383467",
            "0xF197": "GW"
        },
        "DID_Security_21": {
            "0xFA19": "SecurityData"
        },
        "DID_IO_Control": []
    },
```

## Usage
1. Run `uds-server-simulator`, and it will initialize information from `config.json`. If you don't use the `-e` parameter, the program will use the default `CURRENT_ECU` value defined in `config.json`.

    ```
    Usage:   
        uds-server-simulator [options] <CAN interface> 

    Options:  
        -e <ecu name>	ecu name: GW TBOX IVI HUT PKE ESP TPMS   
        -h                  print this help menu  

    Examples:   
        ./uds-server-simulator -e TBOX can0  
    ```

2. You can use `cansend` and `candump` from [can-utils](https://github.com/linux-can/can-utils.git) to send and monitor can bus data.   

    ![usage2-1](./pic/usage2-1.png) 
    
    Of course, you can use other socket can tools to send, receive, and even scan diagnostic can data, like [CANDetective](https://github.com/Honinb0n/CANDetective.git "coming soon in a few weeks").

    Have a happy UDS hacking!

### TransferData

This simulator now is support the 0x34, 0x35, 0x36, 0x37 services. You can perform the following upload and download operations to the simulated memory space:

1. Enter the programming session.
2. Request for security access.
3. Send download or upload request. (Available space: `0x0000 - 0xFFFF`)
    - eg. `703#0734002200000019`
        - `0022`: fixed hard-coded: uncompressed and unencrypted, memoryAddressLength and memorySizeLength are both 2 bytes
        - `0000`: memoryAddress
        - `0019`: memorySize
4. Transferdata.
5. RequestTransferExit.

## Acknowledgments
The software refers to some excellent open source projects.

Special thanks to:

* Craig Smith - uds-server: <https://github.com/zombieCraig/uds-server.git>

## License
GNU General Public License v2.0



