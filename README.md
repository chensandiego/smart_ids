# smart_ids

will process wireshark pcap file to determine any potential threat

To use this feature, run the following command:

1 python ids.py --mode monitor

This will start the monitoring process. Any new PCAP files that are added to the wireshark_pcapoutput directory will be processed,
and any threats will be detected. The processed files will then be moved to the processed_pcaps directory.

I recommend you to test this new feature by adding some PCAP files to the wireshark_pcapoutput directory.
