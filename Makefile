KMOD=	mac_nonet

SRCS=	vnode_if.h \
		mac_nonet.c

.include <bsd.kmod.mk>

