import base64
import hashlib
from oprf import data, mask

def blind(input):
    zPad = bytes(128)
    libStr = bytes([0, 64])
    dstPrime = bytes([
        72, 97, 115, 104, 84, 111, 71, 114, 111, 117,
        112, 45, 79, 80, 82, 70, 86, 49, 45, 0,
        45, 114, 105, 115, 116, 114, 101, 116, 116, 111,
        50, 53, 53, 45, 83, 72, 65, 53, 49, 50,
        40])
    b0 = hashlib.sha512(zPad + input.encode('utf-8') + libStr + bytes([0]) + dstPrime).digest()
    d = data.hash(b0 + bytes([1]) + dstPrime)
    m = mask()
    return m.to_base64(), m.mask(d).to_base64()


def finalize(input, blindElement, evaluatedElement):
    # process input
    m = mask().from_base64(blindElement)
    d = data().from_base64(evaluatedElement)
    
    # unblind
    unblinded = m.unmask(d)
    finalizeDST = bytes([70, 105, 110, 97, 108, 105, 122, 101])

    # hash
    hash = hashlib.sha512(
        bytes([len(input)>>8, len(input)&0xff]) + input.encode('utf-8') +
        bytes([0, 32]) + unblinded + finalizeDST).digest()
    return base64.b64encode(hash)
