"use client";
import Image from 'next/image';
import './globals.css';
import Navbar from '../components/Navbar';
import AOS from 'aos';
import 'aos/dist/aos.css';
import { useEffect, useState } from 'react';
import "swiper/css";
import "swiper/css/effect-cards";
import IntroVideoSection from '../components/Review/IntroVideoSection';
import { Dialog, DialogPanel, DialogBackdrop } from '@headlessui/react'
import { Send, Phone, Mail, MapPin, Facebook, Twitter, Linkedin } from "lucide-react"

export default function Home() {
     const [formData, setFormData] = useState({
          name: '',
          email: '',
          phone: '',
          question: '',
     });
     const [open1, setOpen1] = useState(false)
     const [open2, setOpen2] = useState(false)
     const [open3, setOpen3] = useState(false)
     const [open4, setOpen4] = useState(false)
     const [open5, setOpen5] = useState(false)


     useEffect(() => {
          oncanplay
          AOS.init({
               duration: 1000,
               easing: 'ease-out',
               once: true
          });
     }, []);

     const handleChange = (e) => {
          const { name, value } = e.target;
          setFormData((prev) => ({
               ...prev,
               [name]: value,
          }));
     };

     const handleSubmit = () => {
          alert("Bạn gửi thông tin thành công")
          // Chỉ reset input, không làm gì thêm
          setFormData({
               name: '',
               email: '',
               phone: '',
               question: '',
          });
     };

     return (
          <main>
               {/* Hero Section */}
               <section style={{ position: 'relative', overflow: 'visible' }} id='#' className='relative w-full h-screen max-h-[848px]'>
                    <Image src='/assets/images/web/header.png' alt='Header Image' fill priority className='object-cover brightness-[0.85]' />
                    <div data-aos='fade-down '>
                         <div className='absolute inset-0 w-full h-full bg-gradient-to-b from-black/40 to-Taohtransparent'>
                              {/* Navigation */}
                              <Navbar />

                              {/* Hero Content */}
                              <div className='mt-[150px] sm:mt-0 container mx-auto px-4 h-[calc(100%-60px)] flex items-center'>
                                   <div className='flex flex-col lg:flex-row items-center justify-between gap-8 w-full'>
                                        <div data-aos='fade-down' className='lg:ml-[100px] text-white w-full lg:max-w-[600px]'>
                                             <p className='text-[20px] font-light leading-[34px] w-full lg:w-[512px] text-center lg:text-left animate-fadeIn'>🔷 Giới thiệu về chúng tôi</p>
                                             <h1 className='text-[36px] lg:text-[48px] leading-[46px] lg:leading-[62.5px] bg-gradient-to-r from-[#00FF7B] to-[#00E0FF] text-transparent bg-clip-text font-bold w-full lg:w-[536px] text-center lg:text-left mt-2 '>Tạo ra các giải pháp thông minh và độc đáo</h1>
                                             <p className='text-[18px] font-light lg:text-[20px] leading-[30px] lg:leading-[34px] mt-4 w-full lg:w-[640px] text-center text-justify'>EG Team là một đội ngũ công nghệ trong lĩnh vực Blockchain, Web3 và DePIN. Chúng tôi quy tụ những bộ óc đổi mới với kinh nghiệm thực chiến trong việc xây dựng các nền tảng Blockchain hiệu suất cao, bảo mật và thân thiện với người dùng.</p>
                                             {/* <div className='mt-8 flex justify-center lg:justify-start'>
                                                  <button className='px-8 py-3 bg-gradient-to-r from-[#00FF7B] to-[#00E0FF] text-black font-medium rounded-full hover:shadow-lg transition-all duration-300 transform hover:scale-105'>Tìm hiểu thêm</button>
                                             </div> */}
                                        </div>

                                        <div data-aos='fade-down'>
                                             <div className='w-full lg:mr-[100px] lg:w-[500px] lg:h-[500px] h-[300px] relative mt-8 lg:mt-0 '>
                                                  <Image src='/assets/images/web/teamwork.png' alt='Minh họa' fill className='object-contain' />
                                             </div>
                                        </div>
                                   </div>
                              </div>
                         </div>
                    </div>
               </section>

               {/* About Section */}
               <section className='relative w-full py-20'>
                    <Image src='/assets/images/web/Group.png' alt='Background Image' fill className='object-cover' />
                    <div className='container mx-auto relative z-10'>
                         <div data-aos='fade-right' className='flex flex-col lg:flex-row items-center justify-around gap-12'>
                              <div className='w-full h-[300px] lg:w-[623px] lg:h-[501px] relative lg:ml-[46px] animate-float'>
                                   <Image src='/assets/images/web/people.png' alt='Minh họa' fill className='object-contain' />
                              </div>

                              <div className='lg:mr-[100px] max-w-[660px]'>
                                   <h2 className='text-[24px] md:text-[30px] lg:text-[36px] font-bold leading-[36px] md:leading-[42px] lg:leading-[48px] bg-gradient-to-r from-[#00D768] to-[#007137] text-transparent bg-clip-text text-center lg:text-left mb-6'>PHÁT TRIỂN GIẢI PHÁP BLOCKCHAIN</h2>
                                   <p className='text-[#8198A4] text-[16px] md:text-[17px] lg:text-[18px] font-normal leading-[26px] md:leading-[28px] lg:leading-[30px] text-justify'>
                                        EG TEAM là đội ngũ chuyên gia nghiên cứu và phát triển công nghệ tiên tiến, tập trung vào các lĩnh vực chủ chốt như Blockchain, Trí tuệ nhân tạo (AI), Web3, Hạ tầng phi tập trung (DePIN), Sàn giao dịch tài sản số và Internet of Things (IoT). Với sứ mệnh kiến tạo những giải pháp đột phá và đóng góp vào sự phát triển của nền công nghệ số toàn cầu, EG TEAM không ngừng đổi mới và ứng dụng công nghệ để mang lại giá trị thực tiễn cho cộng đồng và doanh nghiệp.
                                        Chúng tôi đồng hành cùng các đối tác trong việc xây dựng hệ sinh thái công nghệ hiện đại, minh bạch và bền vững.
                                   </p>
                              </div>
                         </div>
                    </div>
               </section>

               {/* Team Section */}
               <section id='team' className='relative w-full py-20 overflow-hidden bg-team-bg'>
                    <div className='absolute inset-0 z-0'>
                         <Image src='/assets/images/web/background.png' alt='Background' fill className='object-cover opacity-20' />
                         <div className='absolute inset-0 bg-team-rays'></div>
                    </div>

                    <div data-aos='fade-left' className='relative z-10'>
                         <div className='text-center'>
                              <h2 className='text-[28px] md:text-[32px] lg:text-[40px] font-bold text-center bg-gradient-to-r from-[#00FF7B] to-[#00E0FF] text-transparent bg-clip-text'>THÀNH VIÊN CHỦ CHỐT</h2>
                              <div className='h-[2px] w-full max-w-[800px] mx-auto bg-gradient-to-r from-transparent via-[#00E0FF] to-transparent mt-3'></div>
                         </div>
                    </div>

                    <div className='container mx-auto px-4 mt-20 relative z-10'>
                         {/* Decorative Elements */}
                         <div className='absolute w-4 h-4 bg-[#00E0FF] rounded-full top-10 right-10 animate-pulse-slow'></div>
                         <div className='absolute w-6 h-6 border-2 border-[#00D768] top-40 left-10 rotate-45'></div>
                         <div className='absolute w-3 h-3 bg-[#00FF7B] rounded-full left-[15%] bottom-20 animate-pulse'></div>
                         <div className='absolute w-8 h-8 border border-[#00E0FF]/30 rounded-full right-[15%] top-[30%] animate-pulse-slow'></div>

                         {/* Team Members Carousel */}
                         <div data-aos='fade-left' className='relative px-10 '>
                              <div className='flex flex-wrap justify-center gap-8 md:gap-6'>
                                   {/* Team Member 1 */}
                                   <div className='w-full md:w-[220px] group transition-all duration-500 hover:scale-105 cursor-pointer'>
                                        <div onClick={() => setOpen1(true)} className='relative p-6 rounded-2xl border border-[#00E0FF] bg-white/5 backdrop-blur-sm transition-all duration-300 group-hover:shadow-[0_0_20px_rgba(0,224,255,0.4)] h-full'>
                                             {/* A */}
                                             <div className='w-28 h-28 mx-auto rounded-full overflow-hidden mb-6 bg-gradient-to-b from-[rgba(0,255,123,0.15)] to-[rgba(0,224,255,0.15)] border-2 border-[#00E0FF]/40 group-hover:border-[#00E0FF]/70 transition-all duration-300'>
                                                  <div className='w-full h-full bg-dark-light/80 flex items-center justify-center text-2xl font-bold text-[#00E0FF]/80'>
                                                       <Image src='/assets/images/web/_kieuanh.jpg' alt='Kiều Anh' width={110} height={110} className='rounded-full object-cover' />
                                                  </div>
                                             </div>
                                             <h3 className='text-lg font-bold text-center mb-2 text-[#017479] transition-colors duration-300'>Kiều Anh</h3>
                                             <p className='text-[#00E0FF]/80 text-center text-sm text-[#017479]'>Blockchain Developer</p>
                                             <div className='h-0.5 w-0 group-hover:w-full bg-gradient-to-r from-[#00FF7B]/50 to-[#00E0FF]/50 mt-4 transition-all duration-500 mx-auto'></div>
                                        </div>

                                        {/* Modal Dialog */}
                                        <Dialog open={open1} onClose={() => setOpen1(false)} className="relative z-50">
                                             <DialogBackdrop
                                                  transition
                                                  className="fixed inset-0 bg-black/50 transition-opacity data-[closed]:opacity-0 data-[enter]:duration-300 data-[enter]:ease-out data-[leave]:duration-200 data-[leave]:ease-in"
                                             />

                                             <div className="fixed inset-0 z-10 w-screen overflow-y-auto">
                                                  <div className="flex min-h-full items-center justify-center p-4 text-center">
                                                       <DialogPanel transition className="relative transform overflow-hidden rounded-2xl bg-white text-left shadow-xl transition-all data-[closed]:translate-y-4 data-[closed]:opacity-0 data-[enter]:duration-300 data-[enter]:ease-out data-[leave]:duration-200 data-[leave]:ease-in w-[700px] data-[closed]:scale-95">
                                                            {/* Header Section */}
                                                            <div className="bg-gradient-to-r from-cyan-100 to-cyan-50 p-6 relative">
                                                                 <div className="flex items-start gap-4">
                                                                      <div className="w-20 h-20 bg-gray-200 rounded-full border-4 border-cyan-200 flex-shrink-0 overflow-hidden">
                                                                           <Image
                                                                                src="/assets/images/web/_kieuanh.jpg"
                                                                                alt="Kiều Anh"
                                                                                width={110}
                                                                                height={110}
                                                                                className="rounded-full object-cover"
                                                                           />
                                                                      </div>
                                                                      <div className="flex-1 pt-2">
                                                                           <h1 className="text-2xl font-bold text-gray-900 mb-1">Nguyễn Tô Kiều Anh</h1>
                                                                           <p className="text-cyan-500 font-semibold text-lg mb-2">Thành viên</p>
                                                                      </div>
                                                                 </div>
                                                            </div>

                                                            {/* Content Section */}
                                                            <div>
                                                                 {/* Introduction */}
                                                                 <div className='max-h-[500px] overflow-y-auto p-4'>
                                                                      <h2 className="text-base font-semibold text-gray-900 mb-1">Thông tin:</h2>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium">
                                                                           Họ và tên: Nguyễn Tô Kiều Anh.
                                                                      </p>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium">
                                                                           Chuyên môn: Công nghệ Blockchain, Smart Contract.
                                                                      </p>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium mb-3">
                                                                           Kinh nghiệm: Sinh viên thực tập 1 năm trong lĩnh vực phát triển Web3, Smart Contract.
                                                                      </p>
                                                                      <h2 className="text-base font-semibold text-gray-900 mb-1">Giới thiệu:</h2>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium mb-3">
                                                                           Tôi là Nguyễn Tô Kiều Anh – Blockchain Developer của nhóm EG Team. Với niềm đam mê sâu sắc đối với công nghệ sổ cái phân tán, tôi đã đồng hành cùng đội ngũ phát triển một nền tảng blockchain có tính minh bạch, bảo mật cao và tối ưu cho các ứng dụng thực tiễn. Tôi chịu trách nhiệm viết và triển khai các smart contract, xây dựng kiến trúc hệ thống Web3, tích hợp ví điện tử, và tham gia vào việc phát triển mạng blockchain Layer-1 riêng biệt. Ngoài ra, tôi cũng góp phần vào việc kiểm tra bảo mật hợp đồng thông minh và cải tiến cơ chế đồng thuận phù hợp với yêu cầu hệ thống.
                                                                      </p>
                                                                      <h2 className="text-base font-semibold text-gray-900 mb-1">Tầm nhìn:</h2>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium mb-3">
                                                                           Tôi tin rằng Blockchain không chỉ là công nghệ của tương lai, mà là chìa khóa để xây dựng niềm tin số trong xã hội hiện đại. Với định hướng phát triển công nghệ vì cộng đồng, chúng tôi hướng đến việc tạo ra các giải pháp phi tập trung không chỉ an toàn và hiệu quả, mà còn dễ tiếp cận và ứng dụng vào đời sống, doanh nghiệp tại địa phương và trên toàn cầu.
                                                                      </p>

                                                                      <h2 className="text-base font-semibold text-gray-900 mb-1">Vai trò trong EG Team:</h2>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium mb-3">
                                                                           - Thiết kế, viết và triển khai các Smart Contract bằng Solidity trên Ethereum và các nền tảng tương thích EVM.<br></br>
                                                                           - Tham gia xây dựng mạng Blockchain riêng với cơ chế đồng thuận tùy chỉnh. <br></br>
                                                                           - Tích hợp hệ thống Web3 và ví điện tử (Metamask, WalletConnect, v.v.). <br></br>
                                                                           - Thực hiện kiểm thử bảo mật và tối ưu hiệu năng của hệ thống phi tập trung. <br></br>
                                                                           - Phối hợp cùng nhóm kỹ thuật để trình bày giải pháp tại các sự kiện công nghệ, workshop và buổi pitching sản phẩm. <br></br>
                                                                      </p>
                                                                 </div>
                                                            </div>
                                                       </DialogPanel>
                                                  </div>
                                             </div>
                                        </Dialog>
                                   </div>

                                   {/* Team Member 2 */}
                                   <div className='w-full md:w-[220px] group transition-all duration-500 hover:scale-105 cursor-pointer'>
                                        <div onClick={() => setOpen2(true)} className='relative p-6 rounded-2xl border border-[#00E0FF] bg-white/5 backdrop-blur-sm transition-all duration-300 group-hover:shadow-[0_0_20px_rgba(0,224,255,0.4)] h-full'>
                                             <div className='w-28 h-28 mx-auto rounded-full overflow-hidden mb-6 bg-gradient-to-b from-[rgba(0,255,123,0.15)] to-[rgba(0,224,255,0.15)] border-2 border-[#00E0FF]/40 group-hover:border-[#00E0FF]/70 transition-all duration-300'>
                                                  <div className='w-full h-full bg-dark-light/80 flex items-center justify-center text-2xl font-bold text-[#00E0FF]/80'>
                                                       <Image src='/assets/images/web/_minhduy.jpg' alt='Minh Duy' width={110} height={110} className='rounded-full object-cover' />
                                                  </div>
                                             </div>
                                             <h3 className='text-lg font-bold text-center text-[#017479] mb-2 transition-colors duration-300'>Minh Duy</h3>
                                             <p className='text-center text-sm text-[#017479]'>AIoT</p>
                                             <div className='h-0.5 w-0 group-hover:w-full bg-gradient-to-r from-[#00FF7B]/50 to-[#00E0FF]/50 mt-4 transition-all duration-500 mx-auto'></div>
                                        </div>
                                        {/* Modal Dialog */}
                                        <Dialog open={open2} onClose={() => setOpen2(false)} className="relative z-50">
                                             <DialogBackdrop transition className="fixed inset-0 bg-black/50 transition-opacity data-[closed]:opacity-0 data-[enter]:duration-300 data-[enter]:ease-out data-[leave]:duration-200 data-[leave]:ease-in" />

                                             <div className="fixed inset-0 z-10 w-screen overflow-y-auto">
                                                  <div className="flex min-h-full items-center justify-center p-4 text-center">
                                                       <DialogPanel transition className="relative transform overflow-hidden rounded-2xl bg-white text-left shadow-xl transition-all data-[closed]:translate-y-4 data-[closed]:opacity-0 data-[enter]:duration-300 data-[enter]:ease-out data-[leave]:duration-200 data-[leave]:ease-in w-[700px] data-[closed]:scale-95">
                                                            {/* Header Section */}
                                                            <div className="bg-gradient-to-r from-cyan-100 to-cyan-50 p-6 relative">
                                                                 <div className="flex items-start gap-4">
                                                                      <div className="w-20 h-20 bg-gray-200 rounded-full border-4 border-cyan-200 flex-shrink-0 overflow-hidden">
                                                                           <Image
                                                                                src="/assets/images/web/_minhduy.jpg"
                                                                                alt="Minh Duy"
                                                                                width={110}
                                                                                height={110}
                                                                                className="rounded-full object-cover"
                                                                           />
                                                                      </div>
                                                                      <div className="flex-1 pt-2">
                                                                           <h1 className="text-2xl font-bold text-gray-900 mb-1">Hồ Minh Duy</h1>
                                                                           <p className="text-cyan-500 font-semibold text-lg mb-2">Thành viên</p>
                                                                      </div>
                                                                 </div>
                                                            </div>

                                                            {/* Content Section */}
                                                            <div>
                                                                 {/* Introduction */}
                                                                 <div className='max-h-[500px] overflow-y-auto p-4'>
                                                                      <h2 className="text-base font-semibold text-gray-900 mb-1">Thông tin:</h2>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium">
                                                                           Họ và tên: Hồ Minh Duy.
                                                                      </p>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium">
                                                                           Chuyên môn: Internet of Things (IoT), Hệ thống tự động hóa, Trí tuệ nhân tạo (AI), Cơ sở dữ liệu PostgreSQL.
                                                                      </p>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium mb-3">
                                                                           Kinh nghiệm: Sinh viên thực tập 6 tháng trong lĩnh vực phát triển hệ thống IoT thông minh, tích hợp cảm biến, điều khiển thiết bị tự động và xử lý dữ liệu bằng AI.
                                                                      </p>
                                                                      <h2 className="text-base font-semibold text-gray-900 mb-1">Giới thiệu:</h2>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium mb-3">
                                                                           Tôi là Hồ Minh Duy – IoT Developer trong nhóm EG Team, nơi chúng tôi không ngừng nghiên cứu và hiện thực hóa các giải pháp tự động hóa thông minh phục vụ đời sống và sản xuất. Với nền tảng chuyên sâu về hệ thống nhúng và trí tuệ nhân tạo, tôi đã cùng đội nhóm thiết kế và triển khai các mô hình IoT tích hợp cảm biến, xử lý dữ liệu thời gian thực, và tự động đưa ra quyết định dựa trên thuật toán học máy. Tôi chịu trách nhiệm phát triển kiến trúc kết nối thiết bị, lưu trữ và phân tích dữ liệu trên PostgreSQL, cũng như tối ưu khả năng vận hành của hệ thống.
                                                                      </p>
                                                                      <h2 className="text-base font-semibold text-gray-900 mb-1">Tầm nhìn:</h2>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium mb-3">
                                                                           Chúng tôi tin rằng IoT và AI sẽ là chìa khóa mở ra một kỷ nguyên mới về tự động hóa và dữ liệu thông minh. Mục tiêu của chúng tôi không chỉ là điều khiển thiết bị từ xa, mà còn là tạo ra những hệ thống có khả năng học hỏi, thích nghi và tối ưu hóa theo từng môi trường ứng dụng – từ nhà ở thông minh đến các nhà máy công nghiệp.
                                                                      </p>

                                                                      <h2 className="text-base font-semibold text-gray-900 mb-1">Vai trò trong EG Team:</h2>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium mb-3">
                                                                           - Thiết kế và phát triển hệ thống IoT với các thiết bị cảm biến, vi điều khiển và kết nối mạng.<br></br>
                                                                           - Tích hợp AI vào quy trình xử lý dữ liệu để phân tích hành vi và ra quyết định tự động. <br></br>
                                                                           - Xây dựng hệ thống lưu trữ và quản lý dữ liệu với PostgreSQL, đảm bảo khả năng mở rộng và truy vấn hiệu quả. <br></br>
                                                                           - Kiểm thử hệ thống thực tế, đo lường hiệu suất và tối ưu luồng dữ liệu từ thiết bị đến backend. <br></br>
                                                                           - Đại diện kỹ thuật trình bày giải pháp tại các buổi demo công nghệ và hội thảo về IoT & AI. <br></br>
                                                                      </p>
                                                                 </div>
                                                            </div>
                                                       </DialogPanel>
                                                  </div>
                                             </div>
                                        </Dialog>
                                   </div>

                                   {/* Team Member 3 - Center (Featured) */}
                                   <div className='w-full md:w-[280px] z-10 group transition-all duration-500 hover:scale-105 cursor-pointer'>
                                        <div onClick={() => setOpen3(true)} className='relative p-7 rounded-2xl border-2 border-[#00E0FF] bg-gradient-to-b from-white/5 to-transparent backdrop-blur-sm transition-all duration-300 group-hover:shadow-[0_0_25px_rgba(0,224,255,0.5)] h-full'>
                                             <div className='absolute -top-4 left-1/2 transform -translate-x-1/2 bg-gradient-to-r from-[#00FF7B] to-[#00D768] text-black text-xs font-bold py-1.5 px-4 rounded-full shadow-lg'>Đội trưởng</div>
                                             <div className='w-36 h-36 mx-auto rounded-full overflow-hidden mb-6 bg-gradient-to-b from-[rgba(0,255,123,0.3)] to-[rgba(0,224,255,0.3)] border-2 border-[#00E0FF] group-hover:shadow-[0_0_15px_rgba(0,224,255,0.5)] transition-all duration-300'>
                                                  <div className='w-full h-full bg-dark-light/70 flex items-center justify-center text-3xl font-bold text-[#00E0FF]'>
                                                       <Image src='/assets/images/web/_hinphat.jpg' alt='Hỉn Phát' width={160} height={160} className='rounded-full object-cover' />
                                                  </div>
                                             </div>
                                             <h3 className='text-xl font-bold text-center mb-2 text-[#017479] transition-colors duration-300'>Lìu Hìn Phát</h3>
                                             <p className='text-[#00E0FF] text-center text-[#017479]'>Blockchain Architect</p>
                                             <div className='h-0.5 w-1/3 group-hover:w-full bg-gradient-to-r from-[#00FF7B] to-[#00E0FF] mt-4 transition-all duration-500 mx-auto'></div>
                                        </div>

                                        {/* Modal Dialog */}
                                        <Dialog open={open3} onClose={() => setOpen3(false)} className="relative z-50">
                                             <DialogBackdrop transition className="fixed inset-0 bg-black/50 transition-opacity data-[closed]:opacity-0 data-[enter]:duration-300 data-[enter]:ease-out data-[leave]:duration-200 data-[leave]:ease-in" />

                                             <div className="fixed inset-0 z-10 w-screen overflow-y-auto">
                                                  <div className="flex min-h-full items-center justify-center p-4 text-center">
                                                       <DialogPanel transition className="relative transform overflow-hidden rounded-2xl bg-white text-left shadow-xl transition-all data-[closed]:translate-y-4 data-[closed]:opacity-0 data-[enter]:duration-300 data-[enter]:ease-out data-[leave]:duration-200 data-[leave]:ease-in w-[700px] data-[closed]:scale-95">
                                                            {/* Header Section */}
                                                            <div className="bg-gradient-to-r from-cyan-100 to-cyan-50 p-6 relative">
                                                                 <div className="flex items-start gap-4">
                                                                      <div className="w-20 h-20 bg-gray-200 rounded-full border-4 border-cyan-200 flex-shrink-0 overflow-hidden">
                                                                           <Image
                                                                                src="/assets/images/web/_hinphat.jpg"
                                                                                alt="Hỉn Phát"
                                                                                width={110}
                                                                                height={110}
                                                                                className="rounded-full object-cover"
                                                                           />
                                                                      </div>
                                                                      <div className="flex-1 mt-3">
                                                                           <h3 className="text-xl font-bold text-gray-900">Lìu Hỉn Phát</h3>
                                                                           <p className="text-cyan-500 font-semibold text-lg">Trưởng Nhóm EG Team</p>
                                                                      </div>
                                                                 </div>
                                                            </div>

                                                            {/* Content Section */}
                                                            <div>
                                                                 {/* Introduction */}
                                                                 <div className='max-h-[500px] overflow-y-auto p-4'>
                                                                      <h2 className="text-base font-semibold text-gray-900 mb-1">Thông tin:</h2>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium">
                                                                           Họ và tên: Lìu Hỉn Phát
                                                                      </p>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium">
                                                                           Chức vụ: Trưởng Nhóm EG Team – Dự án Blockchain Layer 1
                                                                      </p>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium">
                                                                           Chuyên môn: Công nghệ Blockchain, Smart Contract, Bảo mật hệ thống phi tập trung
                                                                      </p>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium mb-3">
                                                                           Kinh nghiệm: Sinh viên thực tập 1 năm trong lĩnh vực phát triển Web3, Smart Contract, và xây dựng mạng Blockchain riêng
                                                                      </p>
                                                                      <h2 className="text-base font-semibold text-gray-900 mb-1">Giới thiệu:</h2>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium mb-3">
                                                                           Tôi là Lìu Hỉn Phát – trưởng nhóm EG Team của dự án Blockchain. Với nền tảng chuyên sâu về Công nghệ Thông tin và niềm đam mê với công nghệ phi tập trung, tôi và đội ngũ đã cùng nhau xây dựng và phát triển một hệ sinh thái Blockchain minh bạch, bảo mật và hướng đến ứng dụng thực tế.
                                                                           Tôi chịu trách nhiệm định hướng kỹ thuật, thiết kế kiến trúc hệ thống Blockchain Layer-1, phát triển các thuật toán đồng thuận (bao gồm cả thuật toán tùy chỉnh như Proof of Tracing), tối ưu hiệu suất và đảm bảo các yếu tố bảo mật cho mạng lưới.
                                                                      </p>
                                                                      <h2 className="text-base font-semibold text-gray-900 mb-1">Tầm nhìn:</h2>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium mb-3">
                                                                           Chúng tôi tin vào một tương lai nơi Blockchain không chỉ là công nghệ, mà còn là nền tảng của sự tin tưởng. Dự án không chỉ đơn thuần giải quyết bài toán phi tập trung, mà còn tạo ra giải pháp phù hợp với nhu cầu thực tế tại địa phương và quốc tế.
                                                                      </p>

                                                                      <h2 className="text-base font-semibold text-gray-900 mb-1">Vai trò trong EG Team:</h2>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium mb-3">
                                                                           Dẫn dắt kiến trúc kỹ thuật và chiến lược phát triển hệ thống.
                                                                           Quản lý và phân công kỹ thuật cho toàn đội.
                                                                           Kiểm duyệt mã nguồn và bảo mật cho toàn bộ hệ thống blockchain.
                                                                           Đại diện kỹ thuật cho các buổi pitching, thuyết trình và hội thảo công nghệ.
                                                                      </p>
                                                                 </div>
                                                            </div>
                                                       </DialogPanel>
                                                  </div>
                                             </div>
                                        </Dialog>
                                   </div>

                                   {/* Team Member 4 */}
                                   <div className='w-full md:w-[220px] group transition-all duration-500 hover:scale-105 cursor-pointer'>
                                        <div onClick={() => setOpen4(true)} className='relative p-6 rounded-2xl border border-[#00E0FF] bg-white/5 backdrop-blur-sm transition-all duration-300 group-hover:shadow-[0_0_20px_rgba(0,224,255,0.4)] h-full'>
                                             <div className='w-28 h-28 mx-auto rounded-full overflow-hidden mb-6 bg-gradient-to-b from-[rgba(0,255,123,0.15)] to-[rgba(0,224,255,0.15)] border-2 border-[#00E0FF]/40 group-hover:border-[#00E0FF]/70 transition-all duration-300'>
                                                  <div className='w-full h-full bg-dark-light/80 flex items-center justify-center text-2xl font-bold text-[#00E0FF]/80'>
                                                       <Image src='/assets/images/web/_haidang.jpg' alt='Chương Toàn' width={110} height={110} className='rounded-full object-cover' />
                                                  </div>
                                             </div>
                                             <h3 className='text-lg font-bold text-center mb-2 text-[#017479] transition-colors duration-300'>Hải Đăng</h3>
                                             <p className='text-[#00E0FF]/80 text-center text-sm text-[#017479]'>Blockchain Developer</p>
                                             <div className='h-0.5 w-0 group-hover:w-full bg-gradient-to-r from-[#00FF7B]/50 to-[#00E0FF]/50 mt-4 transition-all duration-500 mx-auto'></div>
                                        </div>

                                        {/* Modal Dialog */}
                                        <Dialog open={open4} onClose={() => setOpen4(false)} className="relative z-50">
                                             <DialogBackdrop transition className="fixed inset-0 bg-black/50 transition-opacity data-[closed]:opacity-0 data-[enter]:duration-300 data-[enter]:ease-out data-[leave]:duration-200 data-[leave]:ease-in" />

                                             <div className="fixed inset-0 z-10 w-screen overflow-y-auto">
                                                  <div className="flex min-h-full items-center justify-center p-4 text-center">
                                                       <DialogPanel transition className="relative transform overflow-hidden rounded-2xl bg-white text-left shadow-xl transition-all data-[closed]:translate-y-4 data-[closed]:opacity-0 data-[enter]:duration-300 data-[enter]:ease-out data-[leave]:duration-200 data-[leave]:ease-in w-[700px] data-[closed]:scale-95">
                                                            {/* Header Section */}
                                                            <div className="bg-gradient-to-r from-cyan-100 to-cyan-50 p-6 relative">
                                                                 <div className="flex items-start gap-4">
                                                                      <div className="w-20 h-20 bg-gray-200 rounded-full border-4 border-cyan-200 flex-shrink-0 overflow-hidden">
                                                                           <Image
                                                                                src="/assets/images/web/_haidang.jpg"
                                                                                alt="Minh Duy"
                                                                                width={110}
                                                                                height={110}
                                                                                className="rounded-full object-cover"
                                                                           />
                                                                      </div>
                                                                      <div className="flex-1 pt-2">
                                                                           <h1 className="text-2xl font-bold text-gray-900 mb-1">Mai Hải Đăng</h1>
                                                                           <p className="text-cyan-500 font-semibold text-lg mb-2">Thành viên</p>
                                                                      </div>
                                                                 </div>
                                                            </div>

                                                            {/* Content Section */}
                                                            <div>
                                                                 {/* Introduction */}
                                                                 <div className='max-h-[500px] overflow-y-auto p-4'>
                                                                      <h2 className="text-base font-semibold text-gray-900 mb-1">Thông tin:</h2>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium">
                                                                           Họ và tên: Mai Hải Đăng.
                                                                      </p>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium">
                                                                           Chuyên môn: Cyber Security, Blockchain.
                                                                      </p>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium mb-3">
                                                                           Kinh nghiệm: Đã tham gia nhiều cuộc thi Hackathon, có kinh nghiệm xây dựng và triển khai một số ứng dụng phi tập trung (dApp) trên các hệ sinh thái Blockchain khác nhau.
                                                                      </p>
                                                                      <h2 className="text-base font-semibold text-gray-900 mb-1">Giới thiệu:</h2>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium mb-3">
                                                                           Tôi là Mai Hải Đăng, sinh viên Học viện Kỹ thuật mật mã, hiện đang đảm nhiệm vai trò Blockchain Developer tại EG Team – một nhóm sinh viên đam mê nghiên cứu và phát triển các giải pháp công nghệ hiện đại, đặc biệt là trong lĩnh vực tự động hóa thông minh phục vụ đời sống và sản xuất. Với nền tảng vững chắc về Blockchain và An ninh mạng (Cyber Security), tôi luôn hướng đến việc xây dựng những ứng dụng có tính bảo mật cao, minh bạch và có giá trị thực tiễn.
                                                                      </p>
                                                                      <h2 className="text-base font-semibold text-gray-900 mb-1">Tầm nhìn:</h2>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium mb-3">
                                                                           Chúng tôi tin rằng Blockchain không chỉ là một công nghệ, mà còn là chìa khóa mở ra một kỷ nguyên mới – nơi mà niềm tin, sự minh bạch và quyền kiểm soát dữ liệu cá nhân được đặt lên hàng đầu. EG Team hướng đến việc góp phần xây dựng những giải pháp công nghệ bền vững, góp phần vào sự phát triển chung của xã hội số.
                                                                      </p>

                                                                      <h2 className="text-base font-semibold text-gray-900 mb-1">Vai trò trong EG Team:</h2>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium mb-3">
                                                                           - Thiết kế và phát triển các ứng dụng phi tập trung (dApp) dựa trên nền tảng Blockchain.<br></br>
                                                                           - Tích hợp các giao thức bảo mật trong kiến trúc hệ thống. <br></br>
                                                                           - Tham gia nghiên cứu và triển khai các mô hình ứng dụng mới kết hợp giữa Blockchain, AI và IoT. <br></br>
                                                                           - Hỗ trợ team trong các cuộc thi công nghệ và các dự án thử nghiệm thực tế. <br></br>
                                                                      </p>
                                                                 </div>
                                                            </div>
                                                       </DialogPanel>
                                                  </div>
                                             </div>
                                        </Dialog>
                                   </div>

                                   {/* Team Member 5 */}
                                   <div className='w-full md:w-[220px] group transition-all duration-500 hover:scale-105 cursor-pointer'>
                                        <div onClick={() => setOpen5(true)} className='relative p-6 rounded-2xl border border-[#00E0FF] bg-white/5 backdrop-blur-sm transition-all duration-300 group-hover:shadow-[0_0_20px_rgba(0,224,255,0.4)] h-full'>
                                             <div className='w-28 h-28 mx-auto rounded-full overflow-hidden mb-6 bg-gradient-to-b from-[rgba(0,255,123,0.15)] to-[rgba(0,224,255,0.15)] border-2 border-[#00E0FF]/40 group-hover:border-[#00E0FF]/70 transition-all duration-300'>
                                                  <div className='w-full h-full bg-dark-light/80 flex items-center justify-center text-2xl font-bold text-[#00E0FF]/80'>
                                                       <Image src='/assets/images/web/_chuongtoan.jpg' alt='Chương Toàn' width={110} height={110} className='mt-2 rounded-full object-cover' />
                                                  </div>
                                             </div>
                                             <h3 className='text-lg font-bold text-center mb-2 text-[#017479] transition-colors duration-300'>Chương Toàn</h3>
                                             <p className='text-[#00E0FF]/80 text-center text-sm text-[#017479]'>Backend Developer</p>
                                             <div className='h-0.5 w-0 group-hover:w-full bg-gradient-to-r from-[#00FF7B]/50 to-[#00E0FF]/50 mt-4 transition-all duration-500 mx-auto'></div>
                                        </div>

                                        {/* Modal Dialog */}
                                        <Dialog open={open5} onClose={() => setOpen5(false)} className="relative z-50">
                                             <DialogBackdrop transition className="fixed inset-0 bg-black/50 transition-opacity data-[closed]:opacity-0 data-[enter]:duration-300 data-[enter]:ease-out data-[leave]:duration-200 data-[leave]:ease-in" />

                                             <div className="fixed inset-0 z-10 w-screen overflow-y-auto">
                                                  <div className="flex min-h-full items-center justify-center p-4 text-center">
                                                       <DialogPanel transition className="relative transform overflow-hidden rounded-2xl bg-white text-left shadow-xl transition-all data-[closed]:translate-y-4 data-[closed]:opacity-0 data-[enter]:duration-300 data-[enter]:ease-out data-[leave]:duration-200 data-[leave]:ease-in w-[700px] data-[closed]:scale-95">
                                                            <button
                                                                 onClick={() => setOpen5(false)}
                                                                 className="absolute top-4 right-4 text-gray-400 hover:text-gray-600 transition"
                                                                 aria-label="Đóng"
                                                            >
                                                                 &times;
                                                            </button>
                                                            {/* Header Section */}
                                                            <div className="bg-gradient-to-r from-cyan-100 to-cyan-50 p-6 relative">
                                                                 <div className="flex items-start gap-4">
                                                                      <div className="w-20 h-20 bg-gray-200 rounded-full border-4 border-cyan-200 flex-shrink-0 overflow-hidden">
                                                                           <Image
                                                                                src="/assets/images/web/_chuongtoan.jpg"
                                                                                alt="Minh Duy"
                                                                                width={110}
                                                                                height={110}
                                                                                className="rounded-full object-cover"
                                                                           />
                                                                      </div>
                                                                      <div className="flex-1 pt-2">
                                                                           <h1 className="text-2xl font-bold text-gray-900 mb-1">Dương Phương Chương Toàn</h1>
                                                                           <p className="text-cyan-500 font-semibold text-lg mb-2">Thành viên</p>
                                                                      </div>
                                                                 </div>
                                                            </div>

                                                            {/* Content Section */}
                                                            <div>
                                                                 {/* Introduction */}
                                                                 <div className='max-h-[500px] overflow-y-auto p-4'>
                                                                      <h2 className="text-base font-semibold text-gray-900 mb-1">Thông tin:</h2>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium">
                                                                           Họ và tên: Dương Phương Chương Toàn
                                                                      </p>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium">
                                                                           Chuyên môn: Phát triển Backend với Node.js, MySQL, MongoDB, RESTful API
                                                                      </p>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium mb-3">
                                                                           Kinh nghiệm: Sinh viên thực tập 3 tháng trong lĩnh vực phát triển backend, xây dựng API và làm việc với cơ sở dữ liệu quan hệ (MySQL) và NoSQL (MongoDB)
                                                                      </p>
                                                                      <h2 className="text-base font-semibold text-gray-900 mb-1">Giới thiệu:</h2>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium mb-3">
                                                                           Tôi là Dương Phương Chương Toàn – một backend developer với niềm đam mê xây dựng các ứng dụng mạnh mẽ, có khả năng mở rộng và hiệu suất cao. Với kinh nghiệm chuyên sâu về Node.js, tôi có khả năng tạo ra các RESTful API linh hoạt, dễ bảo trì và tích hợp. Tôi có kinh nghiệm làm việc với cả cơ sở dữ liệu quan hệ (MySQL) và NoSQL (MongoDB), cho phép tôi lựa chọn giải pháp lưu trữ phù hợp nhất cho từng dự án.
                                                                      </p>
                                                                      <h2 className="text-base font-semibold text-gray-900 mb-1">Tầm nhìn:</h2>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium mb-3">
                                                                           Tôi tin rằng một hệ thống backend mạnh mẽ là nền tảng cốt lõi cho bất kỳ sản phẩm công nghệ thành công nào. Chúng tôi không chỉ xây dựng những đoạn mã hiệu quả, mà còn phát triển giải pháp đáp ứng nhu cầu thực tế, dễ mở rộng, dễ bảo trì và sẵn sàng tích hợp với nhiều nền tảng khác nhau trong kỷ nguyên số.
                                                                      </p>

                                                                      <h2 className="text-base font-semibold text-gray-900 mb-1">Vai trò trong EG Team:</h2>
                                                                      <p className="text-gray-700 text-sm leading-relaxed text-justify font-medium mb-3">
                                                                           - Thiết kế và phát triển các API backend sử dụng Node.js và Express. <br></br>
                                                                           - Tối ưu cơ sở dữ liệu MySQL và MongoDB cho hiệu năng và tính toàn vẹn dữ liệu. <br></br>
                                                                           - Xây dựng hệ thống xác thực/ủy quyền bằng JWT, OAuth2. <br></br>
                                                                           - Quản lý cấu trúc dự án, kiểm duyệt mã nguồn và hỗ trợ triển khai hệ thống trên môi trường Staging/Production. <br></br>
                                                                           - Tham gia pitching, trình bày giải pháp backend tại các buổi demo nội bộ và hội thảo công nghệ. <br></br>

                                                                      </p>
                                                                 </div>
                                                            </div>
                                                       </DialogPanel>
                                                  </div>
                                             </div>
                                        </Dialog>
                                   </div>
                              </div>
                         </div>
                    </div>
               </section>

               <section id='introduce' className='relative w-full overflow-hidden'>

                    <div data-aos='zoom-out-up' className='container mx-auto px-4'>
                         <IntroVideoSection />
                    </div>
               </section>


               <section id='services' className='relative w-full overflow-hidden'>
                    <div data-aos='zoom-out-up' className='container mx-auto px-4'>
                         <div className='text-center mb-12'>
                              <h2 className='text-[28px] md:text-[32px] lg:text-[36px] font-bold text-center text-[#00D768]'>LĨNH VỰC CHUYÊN MÔN</h2>
                              <div className='h-[2px] w-full max-w-[800px] mx-auto bg-gradient-to-r from-transparent via-[#00E0FF] to-transparent mt-2'></div>
                         </div>

                         <div className='max-w-[1280px] mx-auto'>
                              <div className='grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8 justify-items-center items-center'>
                                   {/* Field 1 */}
                                   <div className='lg:w-[361px] lg:h-[228px] rounded-2xl border border-[#00E0FF]/30 bg-gradient-to-b from-[#00E0FF]/10 to-transparent p-6 hover:shadow-[0_0_15px_rgba(0,224,255,0.2)] transition-all duration-300 group'>
                                        <div className='mx-auto w-12 h-12 mb-4'>
                                             <Image src='/assets/images/web/layer1.png' alt='Blockchain' width={48} height={48} className='text-[#00E0FF]' />
                                        </div>
                                        <p className='text-[#8198A4] pt-2 text-sm leading-[30px] text-justify'>Blockchain Layer 1 &: Nghiên Cứu và Triển Khai Chuỗi Khối Tốc Độ Cao, Bảo Mật, Hỗ Trợ Hợp Đồng Thông Minh</p>
                                   </div>

                                   {/* Field 2 */}
                                   <div className='lg:w-[361px] lg:h-[228px] rounded-2xl border border-[#00E0FF]/30 bg-gradient-to-b from-[#00E0FF]/10 to-transparent p-6 hover:shadow-[0_0_15px_rgba(0,224,255,0.2)] transition-all duration-300 group'>
                                        <div className='mx-auto w-12 h-12 mb-4'>
                                             <Image src='/assets/images/web/dex.png' alt='DEX' width={48} height={48} className='text-[#00E0FF]' />
                                        </div>
                                        <p className='text-[#8198A4] pt-2 text-sm leading-[30px] text-justify'>Sàn Giao Dịch Phi Tập Trung (DEX): Phát Triển Nền Tảng Giao Dịch Minh Bạch, An Toàn Và Tốc Độ Cao</p>
                                   </div>

                                   {/* Field 3 */}
                                   <div className='lg:w-[361px] lg:h-[228px] rounded-2xl border border-[#00E0FF]/30 bg-gradient-to-b from-[#00E0FF]/10 to-transparent p-6 hover:shadow-[0_0_15px_rgba(0,224,255,0.2)] transition-all duration-300 group'>
                                        <div className='mx-auto w-12 h-12 mb-4'>
                                             <Image src='/assets/images/web/cex.png' alt='DeFi' width={48} height={48} className='text-[#00E0FF]' />
                                        </div>
                                        <p className='text-[#8198A4] pt-2 text-sm leading-[22px]'>Sàn Giao Dịch Tập Trung (CEX): Thiết Kế Và Vận Hành Hệ Thống CEX Với Hiệu Suất Cao, Bảo Mật Đa Tầng, Hỗ Trợ KYC/AML, Quản Lý Tài Sản Và Thanh Khoản, Tích Hợp Đa Chuỗi Và Trải Nghiệm Người Dùng Tối Ưu.</p>
                                   </div>

                                   {/* Field 4 */}
                                   <div className='lg:w-[361px] lg:h-[228px] rounded-2xl border border-[#00E0FF]/30 bg-gradient-to-b from-[#00E0FF]/10 to-transparent p-6 hover:shadow-[0_0_15px_rgba(0,224,255,0.2)] transition-all duration-300 group'>
                                        <div className='mx-auto w-12 h-12 mb-4'>
                                             <Image src='/assets/images/web/al.png' alt='AI' width={48} height={48} className='text-[#00E0FF]' />
                                        </div>
                                        <p className='text-[#8198A4] pt-2 text-sm leading-[30px] text-justify'>AI Ứng Dụng: Phát Triển Giải Pháp AI Phân Tích Dữ Liệu, Xử Lý Ngôn Ngữ Tự Nhiên Và Tự Động Hóa Quy Trình.</p>
                                   </div>

                                   {/* Field 5 */}
                                   <div className='lg:w-[361px] lg:h-[228px] rounded-2xl border border-[#00E0FF]/30 bg-gradient-to-b from-[#00E0FF]/10 to-transparent p-6 hover:shadow-[0_0_15px_rgba(0,224,255,0.2)] transition-all duration-300 group'>
                                        <div className='mx-auto w-12 h-12 mb-4'>
                                             <Image src='/assets/images/web/IoT.png' alt='IoT' width={48} height={48} className='text-[#00E0FF]' />
                                        </div>
                                        <p className='text-[#8198A4] pt-2 text-sm leading-[30px] text-justify'>IoT & Tự Động Hóa: Kết Nối Và Xử Lý Dữ Liệu Từ Thiết Bị Đầu Cuối Qua Mạng Blockchain và AI.</p>
                                   </div>

                                   {/* Field 6 */}
                                   <div className='lg:w-[361px] lg:h-[228px] rounded-2xl border border-[#00E0FF]/30 bg-gradient-to-b from-[#00E0FF]/10 to-transparent p-6 hover:shadow-[0_0_15px_rgba(0,224,255,0.2)] transition-all duration-300 group'>
                                        <div className='mx-auto w-12 h-12 mb-4'>
                                             <Image src='/assets/images/web/DeFin.png' alt='DePIN' width={48} height={48} className='text-[#00E0FF]' />
                                        </div>
                                        <p className='text-[#8198A4] pt-2 text-sm leading-[30px] text-justify'>Hạ Tầng Phi Tập Trung DePIN: Xây Dựng Hệ Thống Hạ Tầng Mạng Phi Tập Trung Phục Vụ Cho Truyền Dữ Liệu, Định Vị Và Đo Lường Thông Minh.</p>
                                   </div>
                              </div>
                         </div>
                    </div>
               </section>

               <footer id="contact" className="mt-10 bg-gradient-to-br from-[#004d4d] via-[#006666] to-[#00cccc] py-16 text-white">
                    <div data-aos="fade-up" data-aos-duration="1000" className="container mx-auto px-4">
                         {/* Main Content */}
                         <div className="flex flex-col gap-10 md:flex-row md:justify-between lg:justify-around">
                              {/* Contact Form */}
                              <div>
                                   <h2 className="text-2xl font-bold mb-8 text-white">Liên hệ với chúng tôi</h2>
                                   <div className="space-y-6">
                                        <div>
                                             <label className="block text-sm font-medium mb-2">
                                                  Họ và tên <span className="text-red-400">*</span>
                                             </label>
                                             <input
                                                  name="name"
                                                  type="text"
                                                  placeholder="Nhập họ và tên"
                                                  value={formData.name}
                                                  onChange={handleChange}
                                                  className="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/20 text-white placeholder-white/60 focus:outline-none focus:ring-2 focus:ring-white/30 focus:border-transparent"
                                             />
                                        </div>

                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                             <div>
                                                  <label className="block text-sm font-medium mb-2">
                                                       Email <span className="text-red-400">*</span>
                                                  </label>
                                                  <input
                                                       name="email"
                                                       type="email"
                                                       placeholder="Nhập email"
                                                       value={formData.email}
                                                       onChange={handleChange}
                                                       className="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/20 text-white placeholder-white/60 focus:outline-none focus:ring-2 focus:ring-white/30 focus:border-transparent"
                                                  />
                                             </div>
                                             <div>
                                                  <label className="block text-sm font-medium mb-2">
                                                       Số điện thoại <span className="text-red-400">*</span>
                                                  </label>
                                                  <input
                                                       name="phone"
                                                       type="tel"
                                                       placeholder="Nhập số điện thoại"
                                                       value={formData.phone}
                                                       onChange={handleChange}
                                                       className="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/20 text-white placeholder-white/60 focus:outline-none focus:ring-2 focus:ring-white/30 focus:border-transparent"
                                                  />
                                             </div>
                                        </div>

                                        <div>
                                             <label className="block text-sm font-medium mb-2">
                                                  Câu hỏi <span className="text-red-400">*</span>
                                             </label>
                                             <textarea
                                                  name="question"
                                                  rows={4}
                                                  placeholder="Nhập câu hỏi"
                                                  value={formData.question}
                                                  onChange={handleChange}
                                                  className="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/20 text-white placeholder-white/60 focus:outline-none focus:ring-2 focus:ring-white/30 focus:border-transparent resize-none"
                                             />
                                        </div>

                                        <button
                                             onClick={handleSubmit}
                                             className="inline-flex items-center gap-2 bg-[#00cccc] hover:bg-[#00b3b3] text-white font-medium px-8 py-3 rounded-lg transition-colors duration-200"
                                        >
                                             Gửi
                                             <Send className="w-4 h-4" />
                                        </button>
                                   </div>
                              </div>

                              {/* Contact Information */}
                              <div>
                                   <h3 className="text-2xl font-bold mb-8 text-white">Thông tin liên hệ</h3>

                                   <div className="space-y-3 mb-5">
                                        <div className="flex items-center gap-2">
                                             <div className="flex items-center">
                                                  <Phone className="w-4 h-4" />
                                             </div>
                                             <span className="text-sm">+84 523 359 915</span>
                                        </div>

                                        <div className="flex items-center gap-2">
                                             <div className="flex items-center">
                                                  <Mail className="w-4 h-4" />
                                             </div>
                                             <span className="text-sm">phat@pionelab.com</span>
                                        </div>

                                        <div className="flex items-center gap-2">
                                             <div className="flex items-center">
                                                  <MapPin className="w-4 h-4" />
                                             </div>
                                             <span className="text-sm">TP.HCM</span>
                                        </div>
                                   </div>
                                   <div className="pt-5 border-t border-white/20"></div>

                                   {/* Social Media */}
                                   <div className="flex gap-4">
                                        <a
                                             href="https://www.youtube.com/@EG-TEAM"
                                             target="_blank"
                                             className="w-10 h-10 rounded-full bg-white/10 hover:bg-[#00cccc]/20 transition flex items-center justify-center text-white group"
                                             rel="noreferrer"
                                        >
                                             <svg
                                                  className="w-6 h-6 group-hover:text-[#00cccc] transition-colors"
                                                  fill="currentColor"
                                                  viewBox="0 0 576 512"
                                                  xmlns="http://www.w3.org/2000/svg"
                                             >
                                                  <path d="M549.7 124.1c-6.3-23.7-24.9-42.4-48.6-48.6C456.5 64 288 64 288 64s-168.5 0-213.1 11.5c-23.7 6.3-42.4 24.9-48.6 48.6C16.8 168.5 16.8 256 16.8 256s0 87.5 9.5 131.9c6.3 23.7 24.9 42.4 48.6 48.6C119.5 448 288 448 288 448s168.5 0 213.1-11.5c23.7-6.3 42.4-24.9 48.6-48.6 9.5-44.4 9.5-131.9 9.5-131.9s0-87.5-9.5-131.9zM232 336V176l142 80-142 80z" />
                                             </svg>
                                        </a>
                                   </div>
                              </div>
                         </div>

                         {/* Footer Bottom */}
                         <div className="mt-8 pt-8 border-t border-white/20 lg:text-center text-sm text-justify">
                              ©{new Date().getFullYear()} <span className="text-[#00cccc] font-medium">EG TEAM</span>. Chúng tôi là những sinh viên đam mê công nghệ.
                         </div>
                    </div>
               </footer>
          </main>
     );
}
