echo "Applying base device tree: ${fdtfile}"
load ${devtype} ${devnum}:${distro_bootpart} ${fdt_addr_r} ${prefix}dtb/${fdtfile}
fdt addr ${fdt_addr_r}

echo "Growing fdt size by 65536"
fdt resize 65536

echo "Configuring fdt_overlay environment variable"
setenv fdt_overlays spi1-add-cs1 tpm-slb9670

for overlay in ${fdt_overlays}; do
    echo "Applying overlay: $overlay"
    load ${devtype} ${devnum}:${distro_bootpart} ${fdtoverlay_addr_r} ${prefix}dtb/${vendor}/overlays/${overlay}.dtbo
    fdt apply ${fdtoverlay_addr_r}
done

bootefi bootmgr ${fdt_addr_r}
