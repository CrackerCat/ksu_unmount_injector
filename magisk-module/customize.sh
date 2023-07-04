[ ! -d "$MODPATH/libs/$ABI" ] && abort "! $ABI not supported"

if ! $BOOTMODE; then
    abort "! Installing from recovery is not supported"
fi

ui_print "- Install ksuhide"
cp -af "$MODPATH/libs/$ABI/ksuhide" "$MODPATH/ksuhide"

chmod 755 "$MODPATH/ksuhide"
if ! "$MODPATH/ksuhide" check; then
    abort
fi
mkdir -p "$MODPATH/system/etc" "$MODPATH/system/bin"

ui_print "- Enable systemless hosts"
cp -af /system/etc/hosts "$MODPATH/system/etc"

ui_print "- Enable sucompat"
ln "$MODPATH/ksuhide" "$MODPATH/system/bin/ksuhide"
ln -s "./ksuhide" "$MODPATH/system/bin/ksud"