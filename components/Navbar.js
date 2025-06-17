'use client';
import Image from 'next/image';
import Link from 'next/link';
import { useState, useEffect } from 'react';

export default function Navbar() {
     const [scrolled, setScrolled] = useState(false);
     const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

     useEffect(() => {
          const handleScroll = () => {
               const isScrolled = window.scrollY > 10;
               if (isScrolled !== scrolled) {
                    setScrolled(isScrolled);
               }
          };

          window.addEventListener('scroll', handleScroll);
          return () => window.removeEventListener('scroll', handleScroll);
     }, [scrolled]);

     const navLinks = [
          { name: 'Trang chủ', href: '/' },
          { name: 'Đội ngũ', href: '#team' },
          { name: 'Giới thiệu', href: '#introduce' },
          { name: 'Chuyên môn', href: '#services' },
          { name: 'Tài liệu', href: '/docs/about/welcome' },
     ];

     return (
          <nav className={`fixed top-0 left-0 w-full z-50 transition-all duration-300 ${scrolled ? 'bg-gradient-to-br from-[#004d4d] via-[#006666] to-[#00cccc] shadow-lg' : 'bg-black/20'}`}>
               <div className='container mx-auto px-4'>
                    <div className='flex items-center lg:justify-around lg:mx-[-70px] justify-between h-[70px]'>

                         {/* Logo */}
                         <div className='flex-shrink-0'>
                              <Link href='/'>
                                   <div className='relative w-[120px] h-[40px] cursor-pointer transform transition-transform hover:scale-105'>
                                        <Image src='assets/images/web/logo.svg' alt='EG TEAM Logo' fill className='object-contain' priority />
                                   </div>
                              </Link>
                         </div>

                         {/* Desktop Navigation */}
                         <div className='hidden md:flex items-center space-x-8'>
                              {navLinks.map((link) => (
                                   <Link
                                        key={link.name}
                                        href={link.href}
                                        target={link.href === '/docs/about/welcome' ? '_blank' : undefined}
                                        rel={link.href === '/docs/about/welcome' ? 'noopener noreferrer' : undefined}
                                        className='text-white hover:text-secondary-light font-medium text-sm transition-colors relative group'
                                   >
                                        {link.name}
                                        <span className='absolute -bottom-1 left-0 w-0 h-0.5 bg-gradient-to-r from-primary-light to-secondary-light transition-all duration-300 group-hover:w-full'></span>
                                   </Link>
                              ))}
                         </div>

                         {/* Contact Button (Desktop) */}
                         <div className='hidden md:block'>
                              <Link
                                   href='#contact'
                                   className='px-5 py-2 bg-gradient-to-r from-primary-light to-secondary-light text-black font-medium rounded-full hover:shadow-glow transition-all duration-300 transform hover:scale-105'
                              >
                                   Liên hệ ngay
                              </Link>
                         </div>

                         {/* Mobile Menu Button */}
                         <div className='md:hidden flex items-center'>
                              <button onClick={() => setMobileMenuOpen(!mobileMenuOpen)} className='text-white p-2 focus:outline-none'>
                                   <div className='w-6 flex flex-col items-end justify-center gap-1.5'>
                                        <span className={`block h-0.5 bg-white transition-all duration-300 ${mobileMenuOpen ? 'w-6 transform rotate-45 translate-y-2' : 'w-6'}`}></span>
                                        <span className={`block h-0.5 bg-white transition-all duration-300 ${mobileMenuOpen ? 'opacity-0' : 'w-4'}`}></span>
                                        <span className={`block h-0.5 bg-white transition-all duration-300 ${mobileMenuOpen ? 'w-6 transform -rotate-45 -translate-y-2' : 'w-5'}`}></span>
                                   </div>
                              </button>
                         </div>
                    </div>
               </div>

               {/* Mobile Menu */}
               <div className={`md:hidden absolute w-full bg-dark/95 backdrop-blur-md transition-all duration-300 overflow-hidden ${mobileMenuOpen ? 'max-h-screen overflow-y-auto shadow-xl' : 'max-h-0'}`}>
                    <div className='container mx-auto px-4 py-4'>
                         <div className='flex flex-col items-center space-y-4'>
                              {navLinks.map((link) => (
                                   <Link
                                        key={link.name}
                                        href={link.href}
                                        target={link.href === '/docs/about/welcome' ? '_blank' : undefined}
                                        rel={link.href === '/docs/about/welcome' ? 'noopener noreferrer' : undefined}
                                        className='text-white hover:text-secondary-light py-2 border-b border-white/10 font-medium transition-colors w-full'
                                        onClick={() => setMobileMenuOpen(false)}
                                   >
                                        {link.name}
                                   </Link>
                              ))}
                              <Link
                                   href='#contact'
                                   className='w-full text-center px-5 py-2 bg-gradient-to-r from-primary-light to-secondary-light text-black font-medium rounded-full hover:shadow-glow transition-all duration-300 mt-2'
                                   onClick={() => setMobileMenuOpen(false)}
                              >
                                   Liên hệ ngay
                              </Link>
                         </div>
                    </div>
               </div>
          </nav>
     );
}
