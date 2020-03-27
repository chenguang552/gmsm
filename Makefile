
TARGETBIN  := gmsmTestMain
TARGETLIB  := libjni_sign_api.so
  
CC      := g++

LIBS :=  -L./openssl/lib -lcrypto
INCLUDE := -I./openssl/include -I /usr/lib/jvm/java-1.8.0-openjdk-1.8.0.222.b10-0.el7_6.x86_64/include -I /usr/lib/jvm/java-1.8.0-openjdk-1.8.0.222.b10-0.el7_6.x86_64/include/linux/
CFLAGS  := -fPIC -g -Wall -std=c++11 -O3 $(DEFINES) $(INCLUDE)  
CXXFLAGS:= $(CFLAGS) -DHAVE_CONFIG_H
SHARE   :=  -fPIC -shared 
  
SOURCE  := $(wildcard  *.cpp)
        
OBJS    := $(patsubst %.c,%.o,$(patsubst %.cpp,%.o,$(SOURCE)))
  
.PHONY : everything objs clean veryclean rebuild
  
everything : $(TARGETBIN)
  
all : $(TARGETBIN)
  
objs : $(OBJS)
  
rebuild: veryclean everything

clean:
	rm -f *.o	
	
veryclean : clean
	rm -f $(TARGET)
  
$(TARGETBIN) : $(OBJS)
	$(CC) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(LIBS)

test:

jni: $(OBJS)
	$(CC) $(CXXFLAGS) $(SHARE)  -o $(TARGETLIB) $(OBJS) $(LDFLAGS) $(LIBS)
