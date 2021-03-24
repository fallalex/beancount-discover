A big pain point for using ledger-cli or other personal finance software is data entry.
I want my financial data to be background noise with my attention on making sense of my money rather than tracking it and balancing my checkbook.
I need to get my data automatically for me to not dread the days I look at my finances because of the overhead.
Small scripts for each of my account providers seems like a good solution. Sadly most banks dont have a consumer API so you have to rely on CSV files.
many back also dont support proper 2FA using either email for SMS. I rely on google's gmail api for check getting one-time validation codes.

This is the script for discover card. I tried to just use `requests` but ended up going for the more flexible `selenium` in the end.
