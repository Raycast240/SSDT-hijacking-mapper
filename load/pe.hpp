#pragma once

namespace map {
    struct reloc_entry_t {
        std::uint32_t m_to_rva;
        std::uint32_t m_size;
        struct {
            std::uint16_t m_offset : 12;
            std::uint16_t m_type : 4;
        } m_item[ 1 ];
    };

    struct entry_t {
        struct symbols_t {
            std::uint64_t m_mm_allocate_independent_pages;
            std::uint64_t m_mm_free_independent_pages;
            std::uint64_t m_mm_pfn_database;
            std::uint64_t m_mi_get_page_table_pfn_buddy_raw;
        } m_pdb;

        struct offsets_t {
            std::uint64_t m_eprocess_active_process_links;
            std::uint64_t m_kprocess_directory_table_base;
            std::uint64_t m_eprocess_unique_process_id;
            std::uint64_t m_eprocess_active_threads;
            std::uint64_t m_mmpfn_size;
            std::uint64_t m_mmpfn_pte_address;
            std::uint64_t m_eprocess_peb;
        } m_offsets;

        std::uint64_t m_image_base;
        std::uint64_t m_image_size;
        std::uint64_t m_ntoskrnl_base;
        std::uint64_t m_status;
    };
}
