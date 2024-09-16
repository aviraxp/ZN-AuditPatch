# FIXME: logd starts very early in boot process, and ZN can only handle services which is started after post-fs-data for now
resetprop -w sys.boot_completed 0
setprop ctl.restart logd
