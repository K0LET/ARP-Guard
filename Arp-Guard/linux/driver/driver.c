#include <linux/init.h> 
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_arp.h> // Header for ARP-specific netfilter hooks
#include <linux/netfilter_ipv4.h>
#include <linux/if_arp.h>        // Header for ARP packet definitions
#include <linux/if_ether.h> 
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/string.h>


#define MAX_FILE_SIZE 4096  // Maximum file size to read
#define FILE_PATH "/var/lib/ArpGuard/blocked_macs.txt"

char* blocked_macs;

static int read_from_file(const char *filepath, char *data, size_t max_len, ssize_t *len) {
    struct file *file;
    loff_t pos = 0;

    /* Open the file */
    file = filp_open(filepath, O_RDONLY, 0);
    if (!file || IS_ERR(file)) {
        printk("file_access - Error opening file\n");
        return -ENOENT;
    }

    /* Read the file */
    *len = 0;
    while (*len < max_len) {
        ssize_t bytes_read = kernel_read(file, data + *len, max_len - *len, &pos);
        if (bytes_read < 0) {
            printk("file_access - Error reading the file: %d\n", (int)bytes_read);
            filp_close(file, NULL);
            return bytes_read;
        }
        if (bytes_read == 0) {
            break;  // End of file
        }
        *len += bytes_read;
    }
    /* Close the file */
    filp_close(file, NULL);

    return 0;
}


static int allocate_file_memory(void){
    ssize_t len;

    /* Allocate memory for data buffer */
    blocked_macs = kmalloc(MAX_FILE_SIZE, GFP_KERNEL);
    if (!blocked_macs) {
        printk(KERN_EMERG "ARP Gaurd: file_access - Error allocating memory\n");
        return -ENOMEM;
    }

    /* Read from the file */
    int ret = read_from_file(FILE_PATH, blocked_macs, MAX_FILE_SIZE, &len);
    if (ret) {
        kfree(blocked_macs);
        return ret;
    }
    return 0;
}


void mac_array_to_str(const unsigned char *mac_array, char *mac_str) {
    // Format each byte of the MAC address as hexadecimal and concatenate them with colons
    snprintf(mac_str, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac_array[0], mac_array[1], mac_array[2],
             mac_array[3], mac_array[4], mac_array[5]);
}


// Function to be called for each incoming ARP packet
static unsigned int arp_packet_inspect_hook(void *priv,
                                            struct sk_buff *skb,
                                            const struct nf_hook_state *state)
{
    struct arphdr *arp_header;
    struct ethhdr *eth_header;
    
    // Check if the packet is an ARP packet
    eth_header = eth_hdr(skb); // Get the ETHER header
    arp_header = arp_hdr(skb); // Get the ARP header

    char mac_str[18];
    mac_array_to_str(eth_header->h_source, mac_str);
    if (strstr(blocked_macs, mac_str) != NULL){
        printk(KERN_EMERG "ARP Gaurd: ARP packet droped from MAC: %pM\n", eth_header->h_source);
        return NF_DROP;
    }

    return NF_ACCEPT; // Accept the packet
}

// Netfilter hook options for ARP packets
static struct nf_hook_ops arp_nfho = {
    .hook = arp_packet_inspect_hook,      // Callback function
    .hooknum = NF_ARP_IN,                  // Hook point: just after ARP packet has been received
    .pf = NFPROTO_ARP,                     // ARP protocol
    .priority = NF_IP_PRI_FIRST            // Highest priority
};

// Module initialization function
static int __init arp_packet_inspect_init(void)
{
    printk(KERN_EMERG "ARP Gaurd: ARP Packet Inspect Module loaded\n");

    int ret = allocate_file_memory();
     if (ret) {
        kfree(blocked_macs);
        return ret;
    }

    // Register the ARP netfilter hook
    if (nf_register_net_hook(&init_net, &arp_nfho)) {
        printk(KERN_EMERG "ARP Gaurd: Failed to register ARP netfilter hook\n");
        return -EFAULT;
    }

    return 0;
}

// Module exit function
static void __exit arp_packet_inspect_exit(void)
{
    printk(KERN_EMERG "ARP Gaurd: ARP Packet Inspect Module unloaded\n");

    // Unregister the ARP netfilter hook
    nf_unregister_net_hook(&init_net, &arp_nfho);
    kfree(blocked_macs);
}

module_init(arp_packet_inspect_init);
module_exit(arp_packet_inspect_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yoav Kolet");
MODULE_DESCRIPTION("Simple ARP packet inspection module");