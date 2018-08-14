#!/bin/sh
source ~/report_env/bin/activate
cd cyhy-data-extract/
~/pycapscan/jobs/cyhy-data-extract.py -s reporter -c cyhy-data-extract.cfg
rsync --include '*.tbz.gpg' --exclude '*' --times --delete -r cyhy_extracts/ drop.ncats.dhs.gov:/var/www/drop.ncats.dhs.gov/htdocs/