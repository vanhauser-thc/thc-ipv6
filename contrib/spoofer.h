#ifndef SPOOFER_H_
#define SPOOFER_H_
#include "data_structures.h"
#if defined (SPOOFER_C)
#define SPOOFER_EXT
#else
#define SPOOFER_EXT extern
#endif

SPOOFER_EXT void spoofer(MArgs mArgss);

#endif /*SPOOFER_H_ */
