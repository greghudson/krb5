
# Build language
LANG=1033

# Program macros
WIX=wix

CD=cd

RM=del

MAKE=nmake -nologo


# Targets

OUTPATH=.

OBJFILE=$(OUTPATH)\kfw.wixobj

MSIFILE=$(OUTPATH)\kfw.msi

WIXINCLUDES= \
	config.wxi \
	features.wxi \
	files.wxi \
	property.wxi \
	runtime.wxi \
	site-local.wxi \
	lang\strings_$(LANG).wxl \
	lang\ui_$(LANG).wxi \
	lang\config_$(LANG).wxi

CUSTOMDLL=custom\custom.dll

!if !defined(CPU) || "$(CPU)" == ""
CPU=$(PROCESSOR_ARCHITECTURE)
!endif # CPU

!if ( "$(CPU)" == "X86" ) || ( "$(CPU)" == "x86" ) || ( "$(CPU)" == "i386" )
WIXARCH = x86
!elseif ( "$(CPU)" == "AMD64" )
WIXARCH = x64
!else
!error "Architecture $(CPU) not supported by installer"
!endif

all: $(MSIFILE)

$(MSIFILE): kfw.wxs $(WIXINCLUDES)
	$(WIX) build -o $@ kfw.wxs \
		-d "Date=%DATE%" -d "Time=%TIME%" -d "BuildLang=$(LANG)" \
		-loc lang\strings_$(LANG).wxl

$(CUSTOMDLL): custom\custom.cpp
	$(CD) custom
	$(MAKE) -f custom.cpp
	$(CD) ..

clean:
	$(RM) $(OBJFILE)
	$(RM) $(MSIFILE)
	$(CD) custom
	$(MAKE) -f custom.cpp clean
	$(CD) ..
