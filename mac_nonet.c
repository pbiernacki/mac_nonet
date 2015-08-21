#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/ucred.h>

#include <security/mac/mac_policy.h>

SYSCTL_DECL(_security_mac);

static SYSCTL_NODE(_security_mac, OID_AUTO, nonet, CTLFLAG_RW, 0,
        "mac_nonet policy controls");

static int nonet_enabled = 0;
SYSCTL_INT(_security_mac_nonet, OID_AUTO, enabled, CTLFLAG_RW,
        &nonet_enabled, 0, "Enforce mac_nonet policy");

static int nonet_gid = -1;
SYSCTL_INT(_security_mac_nonet, OID_AUTO, gid, CTLFLAG_RW,
        &nonet_gid, 0, "Group ID to disallow network access to");

static int nonet_local_gid = -1;
SYSCTL_INT(_security_mac_nonet, OID_AUTO, local_gid, CTLFLAG_RW,
        &nonet_local_gid, 0, "Group ID with access to AF_LOCAL sockets only");

static int
nonet_socket_check_create(struct ucred *cred, int domain, int type, int proto)
{
    if (!nonet_enabled) {
        return (0);
    }
    if (nonet_gid >= 0) {
        for (int i = 0; i < cred->cr_ngroups; i++) {
            if (nonet_gid == cred->cr_groups[i]) {
                return (1);
            }
        }
    }
    if (nonet_local_gid >= 0 && domain == AF_LOCAL) {
        for (int i = 0; i < cred->cr_ngroups; i++) {
            if (nonet_local_gid == cred->cr_groups[i]) {
                return (1);
            }
        }
    }
    return (0);
}

static struct mac_policy_ops nonet_ops =
{
    .mpo_socket_check_create = nonet_socket_check_create,
};

MAC_POLICY_SET(&nonet_ops, mac_nonet, "MAC/NONET",
        MPC_LOADTIME_FLAG_UNLOADOK, NULL);

