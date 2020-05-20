# Heap Out-of-bounds Read in WhatsApp's media picker affecting WhatsApp for android before version 2.19.352

# Background
A wonky patch to CVE-2019-11933 caused an OOB read on the heap.

# Vulnerability
The patch:
```c
void DDGifSlurp(GifInfo *info, bool decode, bool exitAfterFrame) {
    ...
    do {
        ...
        switch (RecordType) {
            case IMAGE_DESC_RECORD_TYPE:
           
                if (DGifGetImageDesc(gifFilePtr, isInitialPass) == GIF_ERROR) {
                    if (info->rasterBits != NULL) {   // <-- start of patch
                        free(info->rasterBits);
                        info->rasterBits = NULL;
                    }
                    info->rasterSize = 0;
                    break;                            // <-- end of patch
                }
                ...
                if (decode) {
                    ...
                    const uint_fast32_t newRasterSize = gifFilePtr->Image.Width * gifFilePtr->Image.Height;
                    if (newRasterSize > info->rasterSize || widthOverflow > 0 || heightOverflow > 0) {
                        void *tmpRasterBits = reallocarray(info->rasterBits, newRasterSize, sizeof(GifPixelType));
                        ...
                    }
    }while (RecordType != TERMINATE_RECORD_TYPE);
}
```
The patch determines that if an image descriptor was not parsed successfully, it should free the rasterBits buffer and skip the current image. This effectively patches the flow required to trigger CVE-2019-11933.
## Original flow (CVE 2019-11933)
1. Parsing Phase
   1. Parse first image (small)
   1. Allocate rasterBits buffer of size (small height * small width)
   1. Parse second image (large)
   1. DGifSetupDecompress/DGifGetImageDesc returns GIF_ERROR
   1. Skip reallocation
1. Rendering Phase
   1. Render first image (success)
   1. Render second image (OOB)
## Patched flow
1. Parsing Phase
   1. Parse first image (small)
   1. Allocate rasterBits buffer of size (small height * small width)
   1. Parse second image (large)
   1. DGifSetupDecompress/DGifGetImageDesc returns GIF_ERROR
   1. Free rasterBits and set it to NULL
   1. Skip reallocation
1. Rendering Phase
   1. Render does not go through as rasterBits buffer is NULL
Patch forgot to account for a third valid image after the malformed one.
# Vulnerable flow
1. Parsing Phase
   1. Parse first image (small)
   1. Allocate rasterBits buffer of size (small height * small width)
   1. Parse second image (large)
   1. DGifSetupDecompress/DGifGetImageDesc returns GIF_ERROR
   1. Free rasterBits and set it to NULL
   1. Skip reallocation
   1. Parse third image (smaller than image 1 or 2)
   1. Allocate rasterBits buffer
1. Rendering Phase
   1. Render first image
   1. Render second image
   1. Render third image (OOB read)
