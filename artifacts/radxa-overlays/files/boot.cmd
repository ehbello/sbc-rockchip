setenv soc_vendor "rockchip"

echo "Boot script loaded from ${devtype} ${devnum}"

if test -e ${devtype} ${devnum}:${distro_bootpart} ${prefix}boot.env; then
	load ${devtype} ${devnum}:${distro_bootpart} ${fdtoverlay_addr_r} ${prefix}boot.env
	env import -t ${fdtoverlay_addr_r} ${filesize}
fi

echo "Applying DT base: ${fdtfile}"
load ${devtype} ${devnum}:${distro_bootpart} ${fdt_addr_r} ${prefix}dtb/${fdtfile}
fdt addr ${fdt_addr_r}
fdt resize 65536

for overlay in ${overlays}; do
    if load ${devtype} ${devnum}:${distro_bootpart} ${fdtoverlay_addr_r} ${prefix}dtb/${soc_vendor}/overlays/${overlay}.dtbo; then
        echo "Applying DT overlay: $overlay"
        fdt apply ${fdtoverlay_addr_r}
    fi
done

bootefi bootmgr ${fdt_addr_r}
