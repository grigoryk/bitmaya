## june 17, 2023:
- figure out why only downloading at 32kb/s
- don't keep the whole file in memory while downloading
  - write parts to a .parts file as we get them
  - annotate (somehow..) the file so that we know index of parts we wrote
  - annotation header should be constant size, so that we can just append stuff
  - once all parts are fetched, write them in proper order into a final file
  - once final file is validated, delete the .parts file
- read state of existing file, report to peers what we have
  - support for both final files and .parts files