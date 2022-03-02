rule CyclopsBlink_modified_install_upgrade
{
 meta:
 author = "NCSC"
 description = "Detects notable strings identified within the modified
install_upgrade executable, embedded within Cyclops Blink"
 hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
 hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"
 hash3 = "7d61c0dd0cd901221a9dff9df09bb90810754f10"
 hash4 = "438cd40caca70cafe5ca436b36ef7d3a6321e858"
 strings:
 // Format strings used for temporary filenames
 $ = "/pending/%010lu_%06d_%03d_p1"
 $ = "/pending/sysa_code_dir/test_%d_%d_%d_%d_%d_%d"
 // Hard-coded key used to initialise HMAC calculation
 $ = "etaonrishdlcupfm"
 // Filepath used to store the patched firmware image
 $ = "/pending/WGUpgrade-dl.new"
 // Filepath of legitimate install_upgrade executable
 $ = "/pending/bin/install_upgraded"
 // Loop device IOCTL LOOP_SET_FD
 $ = {38 80 4C 00}
 // Loop device IOCTL LOOP_GET_STATUS64
 $ = {38 80 4C 05}
 // Loop device IOCTL LOOP_SET_STATUS64
 $ = {38 80 4C 04}
 // Firmware HMAC record starts with the string "HMAC"
 $ = {3C 00 48 4D 60 00 41 43 90 09 00 00}
 condition:
 (uint32(0) == 0x464c457f) and (6 of them)
}
