/*
* #include "vault_name.h" --- IGNORE ---
* Vault cache system -
* manages the in-memory catalog of vaults, handles serialisation to disk,
* cache implementation for file monitoring
* save infos about files in vaults (hashes, last seen, modified status)
* this vault is isoledd from the rest of the system, and should not have any dependencies
* key function: catalog_load(), catalog_save(), vault_check_files()
* calculate the hash of files in vaults and compare with stored hashes to detect changes
* crc32 is used for hashing (fast and sufficient for change detection, not for security)
* catch function uses crc32 for hashing, and stores the hash in the catalog for later 
* comparison for date.
* declare structs;
* enums;
* function calculating cache
* handling error if calculating cache fail;
* check all vaults and their files + function to update cache if  crc32 function detect changes in files in vaults;
* if check fail, error handling for modified files in vaults, and log info about modified files in vaults;
* log info in real time when changes are detected in files in vaults; 
* if log info in real time fail, error handling for log info in real time fail;
* function save in logs all operations in vaults (create, delete, modify files in vaults);
* function save all errors in logs (if calculating cache fail, if log info in real time fail, if check fail);
*/