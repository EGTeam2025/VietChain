
const GridIcon = (props) => {
  return (
    <svg
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={`fill-current ${props.color}`}>
      <path
        d="M23 19H5.5V16.6667H23V19ZM23 13.1667H5.5V10.8333H23V13.1667ZM23 7.33333H5.5V5H23V7.33333Z"
        fill="currentColor"
      />
      <path
        d="M4.33333 19H2V16.6667H4.33333V19ZM4.33333 13.1667H2V10.8333H4.33333V13.1667ZM4.33333 7.33333H2V5H4.33333V7.33333Z"
        fill="currentColor"
      />
    </svg>
  );
};
export default GridIcon;
