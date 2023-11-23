const c = require('compact-encoding')
const b4a = require('b4a')

const EMPTY = b4a.alloc(0)

const hashes = exports.hashes = {
  preencode (state, m) {
    state.end++ // small uint
  },
  encode (state, m) {
    if (m === 'blake2b') {
      c.uint.encode(state, 0)
      return
    }

    throw new Error('Unknown hash: ' + m)
  },
  decode (state) {
    const n = c.uint.decode(state)
    if (n === 0) return 'blake2b'
    throw new Error('Unknown hash id: ' + n)
  }
}

const signatures = exports.signatures = {
  preencode (state, m) {
    state.end++ // small uint
  },
  encode (state, m) {
    if (m === 'ed25519') {
      c.uint.encode(state, 0)
      return
    }

    throw new Error('Unknown signature: ' + m)
  },
  decode (state) {
    const n = c.uint.decode(state)
    if (n === 0) return 'ed25519'
    throw new Error('Unknown signature id: ' + n)
  }
}

const signer = {
  preencode (state, m) {
    signatures.preencode(state, m.signature)
    c.fixed32.preencode(state, m.namespace)
    c.fixed32.preencode(state, m.publicKey)
  },
  encode (state, m) {
    signatures.encode(state, m.signature)
    c.fixed32.encode(state, m.namespace)
    c.fixed32.encode(state, m.publicKey)
  },
  decode (state) {
    return {
      signature: signatures.decode(state),
      namespace: c.fixed32.decode(state),
      publicKey: c.fixed32.decode(state)
    }
  }
}

const signerArray = c.array(signer)

const multipleSigners = {
  preencode (state, m) {
    state.end++ // flags
    c.uint.preencode(state, m.quorum)
    signerArray.preencode(state, m.signers)
  },
  encode (state, m) {
    c.uint.encode(state, m.allowPatched ? 1 : 0)
    c.uint.encode(state, m.quorum)
    signerArray.encode(state, m.signers)
  },
  decode (state) {
    const flags = c.uint.decode(state)
    return {
      allowPatched: (flags & 1) !== 0,
      quorum: c.uint.decode(state),
      signers: signerArray.decode(state)
    }
  }
}

const manifest = exports.manifest = {
  preencode (state, m) {
    c.uint.preencode(state, 0) // version
    hashes.preencode(state, m.hash)
    c.uint.preencode(state, 2) // type

    if (m.static) {
      c.fixed32.preencode(state, m.static)
    }

    if (m.signer) {
      signer.preencode(state, m.signer)
    }

    if (m.multipleSigners) {
      multipleSigners.preencode(state, m.multipleSigners)
    }
  },
  encode (state, m) {
    c.uint.encode(state, 0) // version
    hashes.encode(state, m.hash)
    c.uint.encode(state, m.signer ? 1 : m.multipleSigners ? 2 : 0)

    if (m.static) {
      c.fixed32.encode(state, m.static)
    }

    if (m.signer) {
      signer.encode(state, m.signer)
    }

    if (m.multipleSigners) {
      multipleSigners.encode(state, m.multipleSigners)
    }
  },
  decode (state) {
    const version = c.uint.decode(state)
    if (version !== 0) throw new Error('Invalid version: ' + version)

    const hash = hashes.decode(state)
    const type = c.uint.decode(state)

    if (type > 2) throw new Error('Unknown type: ' + type)

    return {
      hash,
      static: type === 0 ? c.fixed32.decode(state) : null,
      signer: type === 1 ? signer.decode(state) : null,
      multipleSigners: type === 2 ? multipleSigners.decode(state) : null
    }
  }
}

const node = {
  preencode (state, n) {
    c.uint.preencode(state, n.index)
    c.uint.preencode(state, n.size)
    c.fixed32.preencode(state, n.hash)
  },
  encode (state, n) {
    c.uint.encode(state, n.index)
    c.uint.encode(state, n.size)
    c.fixed32.encode(state, n.hash)
  },
  decode (state) {
    return {
      index: c.uint.decode(state),
      size: c.uint.decode(state),
      hash: c.fixed32.decode(state)
    }
  }
}

const nodeArray = c.array(node)

const wire = exports.wire = {}

wire.handshake = {
  preencode (state, m) {
    c.uint.preencode(state, 1)
    c.fixed32.preencode(state, m.capability)
  },
  encode (state, m) {
    c.uint.encode(state, m.seeks ? 1 : 0)
    c.fixed32.encode(state, m.capability)
  },
  decode (state) {
    const flags = c.uint.decode(state)
    return {
      seeks: (flags & 1) !== 0,
      capability: c.fixed32.decode(state)
    }
  }
}

const requestBlock = {
  preencode (state, b) {
    c.uint.preencode(state, b.index)
    c.uint.preencode(state, b.nodes)
  },
  encode (state, b) {
    c.uint.encode(state, b.index)
    c.uint.encode(state, b.nodes)
  },
  decode (state) {
    return {
      index: c.uint.decode(state),
      nodes: c.uint.decode(state)
    }
  }
}

const requestSeek = {
  preencode (state, s) {
    c.uint.preencode(state, s.bytes)
    c.uint.preencode(state, s.padding)
  },
  encode (state, s) {
    c.uint.encode(state, s.bytes)
    c.uint.encode(state, s.padding)
  },
  decode (state) {
    return {
      bytes: c.uint.decode(state),
      padding: c.uint.decode(state)
    }
  }
}

const requestUpgrade = {
  preencode (state, u) {
    c.uint.preencode(state, u.start)
    c.uint.preencode(state, u.length)
  },
  encode (state, u) {
    c.uint.encode(state, u.start)
    c.uint.encode(state, u.length)
  },
  decode (state) {
    return {
      start: c.uint.decode(state),
      length: c.uint.decode(state)
    }
  }
}

wire.request = {
  preencode (state, m) {
    state.end++ // flags
    c.uint.preencode(state, m.id)
    c.uint.preencode(state, m.fork)

    if (m.block) requestBlock.preencode(state, m.block)
    if (m.hash) requestBlock.preencode(state, m.hash)
    if (m.seek) requestSeek.preencode(state, m.seek)
    if (m.upgrade) requestUpgrade.preencode(state, m.upgrade)
    if (m.priority) c.uint.preencode(state, m.priority)
  },
  encode (state, m) {
    const flags = (m.block ? 1 : 0) | (m.hash ? 2 : 0) | (m.seek ? 4 : 0) | (m.upgrade ? 8 : 0) | (m.manifest ? 16 : 0) | (m.priority ? 32 : 0)

    c.uint.encode(state, flags)
    c.uint.encode(state, m.id)
    c.uint.encode(state, m.fork)

    if (m.block) requestBlock.encode(state, m.block)
    if (m.hash) requestBlock.encode(state, m.hash)
    if (m.seek) requestSeek.encode(state, m.seek)
    if (m.upgrade) requestUpgrade.encode(state, m.upgrade)
    if (m.priority) c.uint.encode(state, m.priority)
  },
  decode (state) {
    const flags = c.uint.decode(state)

    return {
      id: c.uint.decode(state),
      fork: c.uint.decode(state),
      block: flags & 1 ? requestBlock.decode(state) : null,
      hash: flags & 2 ? requestBlock.decode(state) : null,
      seek: flags & 4 ? requestSeek.decode(state) : null,
      upgrade: flags & 8 ? requestUpgrade.decode(state) : null,
      manifest: (flags & 16) !== 0,
      priority: flags & 32 ? c.uint.decode(state) : 0
    }
  }
}

wire.cancel = {
  preencode (state, m) {
    c.uint.preencode(state, m.request)
  },
  encode (state, m) {
    c.uint.encode(state, m.request)
  },
  decode (state, m) {
    return {
      request: c.uint.decode(state)
    }
  }
}

const dataUpgrade = {
  preencode (state, u) {
    c.uint.preencode(state, u.start)
    c.uint.preencode(state, u.length)
    nodeArray.preencode(state, u.nodes)
    nodeArray.preencode(state, u.additionalNodes)
    c.buffer.preencode(state, u.signature)
  },
  encode (state, u) {
    c.uint.encode(state, u.start)
    c.uint.encode(state, u.length)
    nodeArray.encode(state, u.nodes)
    nodeArray.encode(state, u.additionalNodes)
    c.buffer.encode(state, u.signature)
  },
  decode (state) {
    return {
      start: c.uint.decode(state),
      length: c.uint.decode(state),
      nodes: nodeArray.decode(state),
      additionalNodes: nodeArray.decode(state),
      signature: c.buffer.decode(state)
    }
  }
}

const dataSeek = {
  preencode (state, s) {
    c.uint.preencode(state, s.bytes)
    nodeArray.preencode(state, s.nodes)
  },
  encode (state, s) {
    c.uint.encode(state, s.bytes)
    nodeArray.encode(state, s.nodes)
  },
  decode (state) {
    return {
      bytes: c.uint.decode(state),
      nodes: nodeArray.decode(state)
    }
  }
}

const dataBlock = {
  preencode (state, b) {
    c.uint.preencode(state, b.index)
    c.buffer.preencode(state, b.value)
    nodeArray.preencode(state, b.nodes)
  },
  encode (state, b) {
    c.uint.encode(state, b.index)
    c.buffer.encode(state, b.value)
    nodeArray.encode(state, b.nodes)
  },
  decode (state) {
    return {
      index: c.uint.decode(state),
      value: c.buffer.decode(state) || EMPTY,
      nodes: nodeArray.decode(state)
    }
  }
}

const dataHash = {
  preencode (state, b) {
    c.uint.preencode(state, b.index)
    nodeArray.preencode(state, b.nodes)
  },
  encode (state, b) {
    c.uint.encode(state, b.index)
    nodeArray.encode(state, b.nodes)
  },
  decode (state) {
    return {
      index: c.uint.decode(state),
      nodes: nodeArray.decode(state)
    }
  }
}

wire.data = {
  preencode (state, m) {
    state.end++ // flags
    c.uint.preencode(state, m.request)
    c.uint.preencode(state, m.fork)

    if (m.block) dataBlock.preencode(state, m.block)
    if (m.hash) dataHash.preencode(state, m.hash)
    if (m.seek) dataSeek.preencode(state, m.seek)
    if (m.upgrade) dataUpgrade.preencode(state, m.upgrade)
    if (m.manifest) manifest.preencode(state, m.manifest)
  },
  encode (state, m) {
    const flags = (m.block ? 1 : 0) | (m.hash ? 2 : 0) | (m.seek ? 4 : 0) | (m.upgrade ? 8 : 0) | (m.manifest ? 16 : 0)

    c.uint.encode(state, flags)
    c.uint.encode(state, m.request)
    c.uint.encode(state, m.fork)

    if (m.block) dataBlock.encode(state, m.block)
    if (m.hash) dataHash.encode(state, m.hash)
    if (m.seek) dataSeek.encode(state, m.seek)
    if (m.upgrade) dataUpgrade.encode(state, m.upgrade)
    if (m.manifest) manifest.encode(state, m.manifest)
  },
  decode (state) {
    const flags = c.uint.decode(state)

    return {
      request: c.uint.decode(state),
      fork: c.uint.decode(state),
      block: flags & 1 ? dataBlock.decode(state) : null,
      hash: flags & 2 ? dataHash.decode(state) : null,
      seek: flags & 4 ? dataSeek.decode(state) : null,
      upgrade: flags & 8 ? dataUpgrade.decode(state) : null,
      manifest: flags & 16 ? manifest.decode(state) : null
    }
  }
}

wire.noData = {
  preencode (state, m) {
    c.uint.preencode(state, m.request)
  },
  encode (state, m) {
    c.uint.encode(state, m.request)
  },
  decode (state, m) {
    return {
      request: c.uint.decode(state)
    }
  }
}

wire.want = {
  preencode (state, m) {
    c.uint.preencode(state, m.start)
    c.uint.preencode(state, m.length)
  },
  encode (state, m) {
    c.uint.encode(state, m.start)
    c.uint.encode(state, m.length)
  },
  decode (state) {
    return {
      start: c.uint.decode(state),
      length: c.uint.decode(state)
    }
  }
}

wire.unwant = {
  preencode (state, m) {
    c.uint.preencode(state, m.start)
    c.uint.preencode(state, m.length)
  },
  encode (state, m) {
    c.uint.encode(state, m.start)
    c.uint.encode(state, m.length)
  },
  decode (state, m) {
    return {
      start: c.uint.decode(state),
      length: c.uint.decode(state)
    }
  }
}

wire.range = {
  preencode (state, m) {
    state.end++ // flags
    c.uint.preencode(state, m.start)
    if (m.length !== 1) c.uint.preencode(state, m.length)
  },
  encode (state, m) {
    c.uint.encode(state, (m.drop ? 1 : 0) | (m.length === 1 ? 2 : 0))
    c.uint.encode(state, m.start)
    if (m.length !== 1) c.uint.encode(state, m.length)
  },
  decode (state) {
    const flags = c.uint.decode(state)

    return {
      drop: (flags & 1) !== 0,
      start: c.uint.decode(state),
      length: (flags & 2) !== 0 ? 1 : c.uint.decode(state)
    }
  }
}

wire.bitfield = {
  preencode (state, m) {
    c.uint.preencode(state, m.start)
    c.uint32array.preencode(state, m.bitfield)
  },
  encode (state, m) {
    c.uint.encode(state, m.start)
    c.uint32array.encode(state, m.bitfield)
  },
  decode (state, m) {
    return {
      start: c.uint.decode(state),
      bitfield: c.uint32array.decode(state)
    }
  }
}

wire.sync = {
  preencode (state, m) {
    state.end++ // flags
    c.uint.preencode(state, m.fork)
    c.uint.preencode(state, m.length)
    c.uint.preencode(state, m.remoteLength)
  },
  encode (state, m) {
    c.uint.encode(state, (m.canUpgrade ? 1 : 0) | (m.uploading ? 2 : 0) | (m.downloading ? 4 : 0) | (m.hasManifest ? 8 : 0))
    c.uint.encode(state, m.fork)
    c.uint.encode(state, m.length)
    c.uint.encode(state, m.remoteLength)
  },
  decode (state) {
    const flags = c.uint.decode(state)

    return {
      fork: c.uint.decode(state),
      length: c.uint.decode(state),
      remoteLength: c.uint.decode(state),
      canUpgrade: (flags & 1) !== 0,
      uploading: (flags & 2) !== 0,
      downloading: (flags & 4) !== 0,
      hasManifest: (flags & 8) !== 0
    }
  }
}

wire.reorgHint = {
  preencode (state, m) {
    c.uint.preencode(state, m.from)
    c.uint.preencode(state, m.to)
    c.uint.preencode(state, m.ancestors)
  },
  encode (state, m) {
    c.uint.encode(state, m.from)
    c.uint.encode(state, m.to)
    c.uint.encode(state, m.ancestors)
  },
  decode (state) {
    return {
      from: c.uint.encode(state),
      to: c.uint.encode(state),
      ancestors: c.uint.encode(state)
    }
  }
}

wire.extension = {
  preencode (state, m) {
    c.string.preencode(state, m.name)
    c.raw.preencode(state, m.message)
  },
  encode (state, m) {
    c.string.encode(state, m.name)
    c.raw.encode(state, m.message)
  },
  decode (state) {
    return {
      name: c.string.decode(state),
      message: c.raw.decode(state)
    }
  }
}

const uintArray = c.array(c.uint)

const patchEncoding = {
  preencode (state, n) {
    c.uint.preencode(state, n.start)
    c.uint.preencode(state, n.length)
    uintArray.preencode(state, n.nodes)
  },
  encode (state, n) {
    c.uint.encode(state, n.start)
    c.uint.encode(state, n.length)
    uintArray.encode(state, n.nodes)
  },
  decode (state) {
    return {
      start: c.uint.decode(state),
      length: c.uint.decode(state),
      nodes: uintArray.decode(state)
    }
  }
}

const multisigInput = {
  preencode (state, n) {
    state.end++
    c.uint.preencode(state, n.signer)
    c.fixed64.preencode(state, n.signature)
    if (n.patch) patchEncoding.preencode(state, n.patch)
  },
  encode (state, n) {
    c.uint.encode(state, n.patch ? 1 : 0)
    c.uint.encode(state, n.signer)
    c.fixed64.encode(state, n.signature)
    if (n.patch) patchEncoding.encode(state, n.patch)
  },
  decode (state) {
    const flags = c.uint.decode(state)
    return {
      signer: c.uint.decode(state),
      signature: c.fixed64.decode(state),
      patch: (flags & 1) ? patchEncoding.decode(state) : null
    }
  }
}

const multisigInputArray = c.array(multisigInput)

const compactNode = {
  preencode (state, n) {
    c.uint.preencode(state, n.index)
    c.uint.preencode(state, n.size)
    c.fixed32.preencode(state, n.hash)
  },
  encode (state, n) {
    c.uint.encode(state, n.index)
    c.uint.encode(state, n.size)
    c.fixed32.encode(state, n.hash)
  },
  decode (state) {
    return {
      index: c.uint.decode(state),
      size: c.uint.decode(state),
      hash: c.fixed32.decode(state)
    }
  }
}

const compactNodeArray = c.array(compactNode)

exports.multiSignature = {
  preencode (state, s) {
    multisigInputArray.preencode(state, s.proofs)
    compactNodeArray.preencode(state, s.nodes)
  },
  encode (state, s) {
    multisigInputArray.encode(state, s.proofs)
    compactNodeArray.encode(state, s.nodes)
  },
  decode (state) {
    return {
      proofs: multisigInputArray.decode(state),
      nodes: compactNodeArray.decode(state)
    }
  }
}
