# AdvNet 2021 Project - Group files

This repository contains all the group-specific files required to run the AdvNet 2021 project, that is:

- The switches P4 programs, in `p4src`,
- The controller program(s), in `controllers`,
- The link, failure, and traffic inputs, in `inputs`.

For the project documentation, refer to: https://gitlab.ethz.ch/nsg/public/adv-net-2021-project/-/blob/main/README.md

## SLAs

* `prr`: **Packet Reception Ratio** (%) -> Minimal percentage of packets that must be successfully received
* `fct`: **Flow Completion Time** (seconds) -> Time to completion of a TCP flow.
* `delay`: **Delay** (seconds) -> Average one-way delay of UDP packets in a flow
* `wp`: **Way-pointing** (switch) -> All packets must traverse the way-point before being delivered to their destination

|id      |src   |dst   |sport   |dport   |protocol|type |target|
|--------|:----:|:----:|:------:|:------:|:------:|-----|------|
|prr_1   |*     |*     |1-100   |1-100   |TCP     |prr  |100%  |
|prr_2   |*     |*     |1-100   |1-100   |UDP     |prr  |100%  |
|fct_3   |*     |*     |1-100   |1-100   |TCP     |fct  |20s   |
|fct_4   |*     |*     |1-100   |1-100   |TCP     |fct  |15s   |
|fct_5   |*     |*     |1-100   |1-100   |TCP     |fct  |10s   |
|delay_6 |*     |*     |1-100   |1-100   |UDP     |delay|0.017s|
|delay_7 |*     |*     |1-100   |1-100   |UDP     |delay|0.015s|
|delay_8 |*     |*     |1-100   |1-100   |UDP     |delay|0.012s|
|prr_9   |*     |*     |101–200 |101–200 |TCP     |prr  |100%  |
|prr_10  |*     |*     |101–200 |101–200 |UDP     |prr  |100%  |
|fct_11  |*     |*     |101–200 |101–200 |TCP     |fct  |20s   |
|fct_12  |*     |*     |101–200 |101–200 |TCP     |fct  |15s   |
|fct_13  |*     |*     |101–200 |101–200 |TCP     |fct  |10s   |
|delay_14|*     |*     |101–200 |101–200 |UDP     |delay|0.03s |
|delay_15|*     |*     |101–200 |101–200 |UDP     |delay|0.025s|
|delay_16|*     |*     |101–200 |101–200 |UDP     |delay|0.02s |
|prr_17  |*     |*     |201–300 |201–300 |TCP     |prr  |100%  |
|prr_18  |*     |*     |201–300 |201–300 |UDP     |prr  |75%   |
|prr_19  |*     |*     |201–300 |201–300 |UDP     |prr  |95%   |
|prr_20  |*     |*     |201–300 |201–300 |UDP     |prr  |100%  |
|fct_21  |*     |*     |201–300 |201–300 |TCP     |fct  |15s   |
|fct_22  |*     |*     |201–300 |201–300 |TCP     |fct  |10s   |
|delay_23|*     |*     |201–300 |201–300 |UDP     |delay|0.02s |
|delay_24|*     |*     |201–300 |201–300 |UDP     |delay|0.012s|
|prr_25  |*     |*     |301–400 |301–400 |TCP     |prr  |100%  |
|prr_26  |*     |*     |301–400 |301–400 |UDP     |prr  |75%   |
|prr_27  |*     |*     |301–400 |301–400 |UDP     |prr  |95%   |
|prr_28  |*     |*     |301–400 |301–400 |UDP     |prr  |100%  |
|delay_29|*     |*     |301–400 |301–400 |UDP     |delay|0.06s |
|delay_30|*     |*     |301–400 |301–400 |UDP     |delay|0.04s |
|prr_31  |*     |*     |60001--*|60001--*|UDP     |prr  |75%   |
|prr_32  |*     |*     |60001--*|60001--*|UDP     |prr  |95%   |
|prr_33  |*     |*     |60001--*|60001--*|UDP     |prr  |100%  |
|wp_34   |LON_h0|BAR_h0|*       |*       |UDP     |wp   |PAR   |
|wp_35   |POR_h0|GLO_h0|*       |*       |UDP     |wp   |PAR   |
|wp_36   |BRI_h0|BAR_h0|*       |*       |UDP     |wp   |PAR   |
|wp_37   |BER_h0|LIS_h0|*       |*       |UDP     |wp   |MAD   |
|wp_38   |LIS_h0|BER_h0|*       |*       |UDP     |wp   |MAD   |

## Links

* Project Description: https://gitlab.ethz.ch/nsg/public/adv-net-2021-project
* Input Pool: https://gitlab.ethz.ch/nsg/public/adv-net-2021-project-inputpool
