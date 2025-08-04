if(CONFIG_LIBCUPS)

cmake_minimum_required(VERSION 3.12...3.31)
project(libcups)

set(LIBCUPS_SRCS
		cups/zephyr-compat.c
		cups/auth.c
        cups/array.c 
#		cups/auth.c 
		cups/clock.c 
		cups/debug.c
#		cups/dest.c
#		cups/dest-job.c
#		cups/dest-localization.c
#		cups/dest-options.c
		cups/dir.c 
#		cups/dnssd.c
		cups/encode.c 
		cups/file.c 
		cups/form.c 
		cups/getputfile.c 
		cups/globals.c 
		cups/hash.c 
		cups/http.c 
		cups/http-addr.c 
		cups/http-addrlist.c 
		cups/http-support.c 
		cups/ipp.c 
		cups/ipp-file.c 
		cups/ipp-support.c 
		cups/json.c 
		cups/jwt.c 
		cups/langprintf.c 
		cups/language.c 
		cups/md5.c 
		cups/notify.c 
		cups/oauth.c 
		cups/options.c 
		cups/pwg-media.c 
		cups/rand.c 
		cups/raster-error.c 
		cups/raster-stream.c 
		cups/request.c 
		cups/string.c 
		cups/tempfile.c 
		cups/thread.c 
		cups/tls.c 
		cups/transcode.c 
		cups/usersys.c 
		cups/util.c
)
set(LIBCUPS_TEST_SRCS
		cups/fuzzipp.c 
#		cups/rasterbench.c 
		cups/testarray.c 
		cups/testclient.c 
		cups/testclock.c 
		cups/testcreds.c 
		cups/testcups.c 
#		cups/testdest.c 
#		cups/testdnssd.c 
		cups/testfile.c 
		cups/testform.c 
#		cups/testgetdests.c 
		cups/testhash.c 
		cups/testhttp.c 
		cups/testi18n.c 
		cups/testipp.c 
		cups/testjson.c 
		cups/testjwt.c 
		cups/testlang.c 
		cups/testoauth.c 
		cups/testoptions.c 
		cups/testpwg.c 
		cups/testraster.c 
		cups/testtestpage.c 
		cups/testthreads.c 
		cups/tlscheck.c
)

zephyr_interface_library_named(LIBCUPS)

zephyr_include_directories(.)

zephyr_library()
zephyr_library_sources( ${LIBCUPS_SRCS} ${LIBCUPS_TEST_SRCS} )

zephyr_library_compile_options(-D_CUPS_SOURCE  -D_THREAD_SAFE -D_REENTRANT -D_REENTRANT -D_FORTIFY_SOURCE=3 -D__USE_MISC -D_GNU_SOURCE -fPIC  -g -Os -Wall -Wunused -Wno-char-subscripts -Wno-deprecated-declarations -Wno-format-truncation -Wno-format-y2k -Wno-switch -Wno-unused-result)

zephyr_library_compile_options(-U_POSIX_C_SOURCE -D_POSIX_C_SOURCE=200809L -I${ZEPHYR_MBEDTLS_MODULE_DIR}/include)

zephyr_library_link_libraries(LIBCUPS)
target_link_libraries(LIBCUPS INTERFACE zephyr_interface)

endif(CONFIG_LIBCUPS)