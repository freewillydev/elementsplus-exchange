CORE_OBJS := bitstream.o cmr.o dag.o deserialize.o eval.o frame.o jets.o jets-secp256k1.o rsort.o sha256.o type.o typeInference.o
BITCOIN_OBJS := bitcoin/env.o bitcoin/exec.o bitcoin/ops.o bitcoin/bitcoinJets.o bitcoin/primitive.o bitcoin/cmr.o bitcoin/txEnv.o
ELEMENTS_OBJS := elements/env.o elements/exec.o elements/ops.o elements/elementsJets.o elements/primitive.o elements/cmr.o elements/txEnv.o
TEST_OBJS := test.o ctx8Pruned.o ctx8Unpruned.o hashBlock.o regression4.o schnorr0.o schnorr6.o typeSkipTest.o elements/checkSigHashAllTx1.o

# From https://fastcompression.blogspot.com/2019/01/compiler-warnings.html
CWARN := -Werror -Wall -Wextra -Wcast-qual -Wcast-align -Wstrict-aliasing -Wpointer-arith -Winit-self -Wshadow -Wswitch-enum -Wstrict-prototypes -Wmissing-prototypes -Wredundant-decls -Wfloat-equal -Wundef -Wconversion

ifneq ($(doCheck), 1)
CPPFLAGS := $(CPPFLAGS) -DPRODUCTION
endif

CFLAGS := $(CFLAGS) -I include

# libsecp256k1 is full of conversion warnings, so we compile jets-secp256k1.c separately.
jets-secp256k1.o: jets-secp256k1.c
	$(CC) -c $(CFLAGS) $(CWARN) -Wno-conversion $(CPPFLAGS) -o $@ $<

elements/elementsJets.o: elements/elementsJets.c
	$(CC) -c $(CFLAGS) $(CWARN) -Wno-switch-enum -Wswitch $(CPPFLAGS) -o $@ $<

sha256.o: sha256.c
	$(CC) -c $(CFLAGS) $(X86_SHANI_CXXFLAGS) $(CWARN) -Wno-cast-align -Wno-sign-conversion $(CPPFLAGS) -o $@ $<

%.o: %.c
	$(CC) -c $(CFLAGS) $(CWARN) $(CPPFLAGS) -o $@ $<

libBitcoinSimplicity.a: $(CORE_OBJS) $(BITCOIN_OBJS)
	ar rcs $@ $^

libElementsSimplicity.a: $(CORE_OBJS) $(ELEMENTS_OBJS)
	ar rcs $@ $^

# Supply the Haskell bridge archive, runtime library and its runtime search path.
test: $(TEST_OBJS) libElementsSimplicity.a | check-haskell-link
	$(CXX) $^ -o $@ $(LDFLAGS) $(HASKELL_LIBS)

check-haskell-link:
	@test -n "$(strip $(HASKELL_LIBS))" || { echo "Set HASKELL_LIBS to the built Haskell bridge/runtime link flags."; exit 1; }

install: libBitcoinSimplicity.a libElementsSimplicity.a
	mkdir -p $(out)/lib
	cp $^ $(out)/lib/
	cp -R include $(out)/include

check: test
	./test

clean:
	-rm -f test libElementsSimplicity.a $(TEST_OBJS) $(OBJS)

.PHONY: install check clean check-haskell-link
