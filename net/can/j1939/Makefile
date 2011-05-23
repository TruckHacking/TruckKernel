
obj-$(CONFIG_CAN_J1939)	+= can-j1939.o

can-j1939-objs := main.o \
	proc.o bus.o \
	rtnl.o \
	socket.o \
	address-claim.o transport.o \
	promisc.o filter.o

ifeq ($(CONFIG_CAN_J1939_DEBUG),y)
	EXTRA_CFLAGS += -DDEBUG
endif

