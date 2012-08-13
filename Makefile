
# standard make variables

LIB = ../../lib/libgen_funcs.a
CFLAGS = -I../../include -m32 -O3
CC = icc

# library components

$(LIB):	$(LIB)(check_endedness.o)
$(LIB):	$(LIB)(fexists.o)
$(LIB):	$(LIB)(reverse_to_copy.o)
$(LIB):	$(LIB)(reverse_in_place.o)




# component dependencies

$(LIB)(LIB)(check_endedness.o):		size_types.h
$(LIB)(LIB)(fexists.o):			size_types.h
$(LIB)(LIB)(reverse_to_copy.o):		size_types.h
$(LIB)(LIB)(reverse_in_place.o):	size_types.h




