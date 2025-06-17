'use client';
import React from 'react';
import { Swiper, SwiperSlide } from 'swiper/react';

import 'swiper/css';
import 'swiper/css/navigation';
import 'swiper/css/pagination';
import { Pagination, Mousewheel, Keyboard, Navigation } from 'swiper/modules';
import { dataReview } from '../data/Data';

const IntroVideoSection = () => {
     return (
          <section className='relative w-full py-20 overflow-hidden'>
               <div className='container mx-auto px-4'>
                    <div className='text-center mb-12'>
                         <h2 className='text-[28px] md:text-[32px] lg:text-[36px] font-bold text-center text-[#00D768]'>VIDEO GIỚI THIỆU</h2>
                         <div className='h-[2px] w-full max-w-[800px] mx-auto bg-gradient-to-r from-transparent via-[#00E0FF] to-transparent mt-2'></div>
                    </div>

                    <Swiper
                         navigation={true}
                         //   pagination={true}
                         mousewheel={true}
                         keyboard={true}
                         modules={[Navigation, Pagination, Mousewheel, Keyboard]}
                         className='max-w-[1285px] lg:h-[650px] aspect-video mx-auto rounded-3xl border-2 border-[#00E0FF] overflow-hidden group hover:shadow-[0_0_25px_rgba(0,224,255,0.4)] transition-all duration-500'
                    >
                         {dataReview.map((video) => (
                              <SwiperSlide key={video.id}>
                                   <div className='relative w-full h-full'>
                                        <div className='absolute inset-0 bg-gradient-to-b from-[rgba(0,255,123,0.1)] to-[rgba(0,224,255,0.1)] opacity-0 group-hover:opacity-100 transition-opacity duration-500 z-10 pointer-events-none'></div>
                                        <iframe src={video.url} title={video.title} allow='accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture' allowFullScreen className='absolute inset-0 w-full h-full z-0'></iframe>
                                   </div>
                              </SwiperSlide>
                         ))}
                    </Swiper>
               </div>
          </section>
     );
};

export default IntroVideoSection;
