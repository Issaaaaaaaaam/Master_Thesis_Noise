#include "share.h"


#if 0
FILE* rand_bytes_prg = NULL;

void rand_bytes_init() {
  if( NULL == ( rand_bytes_prg = fopen( "/dev/urandom", "rb" ) ) ) {
    abort();
  }
}

void rand_bytes_fini() {
  fclose( rand_bytes_prg );
}

void rand_bytes( uint8_t* x, int n ) {
  if( n != fread( x, sizeof( uint8_t ), n, rand_bytes_prg ) ) {
    abort();
  }
}
#else
void rand_bytes_init() {
  srand( 0 );
}

void rand_bytes_fini() {

}

void rand_bytes( uint8_t* x, int n ) {
  for( int i = 0; i < n; i++ ) {
    x[ i ] = rand() & 0xFF;
  }
}
#endif


void mpi_print(const char *c, const Word *a, int len)
{
  int i;
  
  if ((c != NULL) && (strlen(c) > 0)) printf("%s", c);
  for (i = len - 1; i >= 0; i--) printf(FORMATSTR, a[i]);
  printf("\n");
}
