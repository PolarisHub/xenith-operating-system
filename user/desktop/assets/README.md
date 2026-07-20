# Desktop wallpaper asset

`sedat-wallpaper.png` is the user-supplied source image. The adjacent
`sedat-wallpaper.rgb` is its exact 192x225 row-major RGB8 decode, generated once
for the freestanding desktop so the runtime needs no PNG decoder, heap
allocation, filesystem read, or startup conversion.

The renderer applies a focal-point cover crop and bilinear sampling directly
from the embedded RGB bytes. Keep the dimensions and byte-count assertions in
`src/wallpaper.rs` synchronized if the source image changes.
