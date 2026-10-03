#!/bin/bash
# List SSD model contents into ssd_list.txt and grant anna read access
D="/media/dell/One Touch/mergeops"
{ du -sh "$D"/hf "$D"/hf_models "$D"/nim "$D"/nidm; find "$D"/hf "$D"/hf_models "$D"/nim "$D"/nidm -maxdepth 4 -exec ls -ld {} + ; } > /home/anna/dell_hackathon/ssd_list.txt 2>&1
chown anna /home/anna/dell_hackathon/ssd_list.txt
setfacl -m u:anna:rx /media/dell 2>/dev/null
echo "done"
