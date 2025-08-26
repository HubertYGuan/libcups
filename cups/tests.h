#ifndef CUPS_TESTS_H
#define CUPS_TESTS_H

#ifdef __cplusplus
extern "C" {
#endif

void fuzzipp_main(void *p1, void *p2, void *p3);
void testarray_main(void *p1, void *p2, void *p3);
void testclient_main(void *p1, void *p2, void *p3);
void testclock_main(void *p1, void *p2, void *p3);
void testcreds_main(void *p1, void *p2, void *p3);
void testcups_main(void *p1, void *p2, void *p3);
void testfile_main(void *p1, void *p2, void *p3);
void testform_main(void *p1, void *p2, void *p3);
void testhash_main(void *p1, void *p2, void *p3);
void testhttp_main(void *p1, void *p2, void *p3);
void testi18n_main(void *p1, void *p2, void *p3);
void testipp_main(void *p1, void *p2, void *p3);
void testjson_main(void *p1, void *p2, void *p3);
void testjwt_main(void *p1, void *p2, void *p3);
void testlang_main(void *p1, void *p2, void *p3);
void testoauth_main(void *p1, void *p2, void *p3);
void testoptions_main(void *p1, void *p2, void *p3);
void testpwg_main(void *p1, void *p2, void *p3);
void testraster_main(void *p1, void *p2, void *p3);
void testtestpage_main(void *p1, void *p2, void *p3);
void testthreads_main(void *p1, void *p2, void *p3);
void tlscheck_main(void *p1, void *p2, void *p3);

#ifdef __cplusplus
}
#endif

#endif /* CUPS_TESTS_H */