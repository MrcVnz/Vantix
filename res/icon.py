"""Vantix icon: a two-tone V on a screwed hardware plate, drawn pixel by pixel below.

Each size is its own drawing; nothing is resampled except whole-number upscales of the
32 px art for the large ICO entries. Run `python res/icon.py` to rebuild
res/vantix.ico, res/vantix.png and res/vantix-tray.png (needs Pillow).

K outline   D plate   H plate light edge   d plate dark edge   S/s screw
1 lime highlight   2 lime   3 lime in shadow
"""

import io
import os
import struct

from PIL import Image

PALETTE = {
    'K': (8, 10, 12),
    'D': (24, 29, 36),
    'H': (44, 52, 62),
    'd': (15, 18, 23),
    'S': (150, 160, 170),
    's': (78, 86, 96),
    '1': (214, 255, 122),
    '2': (155, 238, 46),
    '3': (84, 168, 34),
}

ICON_32 = """
................................
................................
....KKKKKKKKKKKKKKKKKKKKKKKK....
...KHHHHHHHHHHHHHHHHHHHHHHHHK...
..KHDDDDDDDDDDDDDDDDDDDDDDDDdK..
..KHDSsDDDDDDDDDDDDDDDDDDSsDdK..
..KHDsKDDDDDDDDDDDDDDDDDDsKDdK..
..KHDDDKKKKKDDDDDDDDKKKKKDDDdK..
..KHDDK12222KDDDDDDK33333KDDdK..
..KHDDK12222KDDDDDDK33333KDDdK..
..KHDDK12222KDDDDDDK33333KDDdK..
..KHDDDK12222KDDDDK33333KDDDdK..
..KHDDDK12222KDDDDK33333KDDDdK..
..KHDDDK12222KDDDDK33333KDDDdK..
..KHDDDDK12222KDDK33333KDDDDdK..
..KHDDDDK12222KDDK33333KDDDDdK..
..KHDDDDK12222KDDK33333KDDDDdK..
..KHDDDDDK12222KK33333KDDDDDdK..
..KHDDDDDK12222KK33333KDDDDDdK..
..KHDDDDDK12222KK33333KDDDDDdK..
..KHDDDDDDK1222233333KDDDDDDdK..
..KHDDDDDDK1222233333KDDDDDDdK..
..KHDDDDDDK1222233333KDDDDDDdK..
..KHDDDDDDDK12222333KDDDDDDDdK..
..KHDDDDDDDK12222333KDDDDDDDdK..
..KHDSsDDDDDKK1222KKDDDDDSsDdK..
..KHDsKDDDDDDDKKKKDDDDDDDsKDdK..
..KHDDDDDDDDDDDDDDDDDDDDDDDDdK..
...KddddddddddddddddddddddddK...
....KKKKKKKKKKKKKKKKKKKKKKKK....
................................
................................
"""

ICON_24 = """
........................
...KKKKKKKKKKKKKKKKKK...
..KHHHHHHHHHHHHHHHHHHK..
.KHDDDDDDDDDDDDDDDDDDdK.
.KHDSDDDDDDDDDDDDDDSDdK.
.KHDDKKKKDDDDDDKKKKDDdK.
.KHDK1222KDDDDK3333KDdK.
.KHDK1222KDDDDK3333KDdK.
.KHDK1222KDDDDK3333KDdK.
.KHDK1222KDDDDK3333KDdK.
.KHDDK1222KDDK3333KDDdK.
.KHDDK1222KDDK3333KDDdK.
.KHDDK1222KDDK3333KDDdK.
.KHDDDK1222KK3333KDDDdK.
.KHDDDK1222KK3333KDDDdK.
.KHDDDK1222KK3333KDDDdK.
.KHDDDDK12223333KDDDDdK.
.KHDDDDK12223333KDDDDdK.
.KHDDDDK12223333KDDDDdK.
.KHDSDDDKK1223KKDDDSDdK.
.KHDDDDDDDKKKKDDDDDDDdK.
..KddddddddddddddddddK..
...KKKKKKKKKKKKKKKKKK...
........................
"""

ICON_16 = """
.KKKKKKKKKKKKKK.
KHHHHHHHHHHHHHHK
KHDKKKDDDDKKKDdK
KHK122KDDK333KdK
KHK122KDDK333KdK
KHK122KDDK333KdK
KHDK122KK333KDdK
KHDK122KK333KDdK
KHDK122KK333KDdK
KHDDK122333KDDdK
KHDDK122333KDDdK
KHDDK122333KDDdK
KHDDDKK12KKDDDdK
KHDDDDDKKDDDDDdK
KHdddddddddddddK
.KKKKKKKKKKKKKK.
"""

HERE = os.path.dirname(os.path.abspath(__file__))


def draw(art):
    rows = art.strip('\n').split('\n')
    size = len(rows)
    assert all(len(row) == size for row in rows), 'every row must be as wide as the art is tall'
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    for y, row in enumerate(rows):
        for x, ch in enumerate(row):
            if ch != '.':
                img.putpixel((x, y), PALETTE[ch] + (255,))
    return img


def upscale(img, factor):
    return img.resize((img.width * factor, img.height * factor), Image.NEAREST)


def write_ico(path, images):
    blobs = []
    for img in images:
        buf = io.BytesIO()
        img.save(buf, 'PNG', optimize=True)
        blobs.append((img.width, buf.getvalue()))
    header = struct.pack('<HHH', 0, 1, len(blobs))
    offset = 6 + 16 * len(blobs)
    entries = b''
    for size, data in blobs:
        entries += struct.pack('<BBBBHHII', size % 256, size % 256, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    with open(path, 'wb') as f:
        f.write(header + entries + b''.join(data for _, data in blobs))


if __name__ == '__main__':
    i16, i24, i32 = draw(ICON_16), draw(ICON_24), draw(ICON_32)
    write_ico(
        os.path.join(HERE, 'vantix.ico'),
        [i16, i24, i32, upscale(i24, 2), upscale(i32, 2), upscale(i32, 4), upscale(i32, 8)],
    )
    upscale(i32, 8).save(os.path.join(HERE, 'vantix.png'), optimize=True)
    # The tray shows 16 px at 100% scaling; a 2:1 image of the 16 px art reduces cleanly.
    upscale(i16, 2).save(os.path.join(HERE, 'vantix-tray.png'), optimize=True)
