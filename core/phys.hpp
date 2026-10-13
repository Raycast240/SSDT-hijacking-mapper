#pragma once

namespace mmu {
    std::uint64_t virtual_to_physical( std::uint64_t va ) {
        auto pa = nt::mm_get_physical_address( reinterpret_cast<void*>( va ) );
        return pa.m_quad_part;
    }
}
