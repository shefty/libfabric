dnl Configury specific to the libfabric general provider

dnl Called to configure this provider
dnl
dnl Arguments:
dnl
dnl $1: action if configured successfully
dnl $2: action if not configured successfully
dnl
AC_DEFUN([FI_GENERAL_CONFIGURE],[
	# Determine if we can support the general provider
	general_happy=0
	AS_IF([test x"$enable_general" != x"no"],
	      [general_happy=1],
	      [general_happy=0])

	AS_IF([test $general_happy -eq 1], [$1], [$2])
])
