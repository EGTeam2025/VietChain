const GiftIcon = (props) => {
  return (
    <svg
      height="20px"
      width="20px"
      viewBox="0 0 50 50"
      xmlns="http://www.w3.org/2000/svg"
      className={`stroke-current-current ${props.color}`}
    >
      <path
        fill="none"
        stroke="currentColor"
        strokeLinecap="round"
        stroke-miterlimit="10"
        strokeWidth="2"
        d="M20 23H2v-9h46v9H30"
      ></path>
      <path
        fill="none"
        stroke="currentColor"
        strokeLinecap="round"
        stroke-miterlimit="10"
        strokeWidth="2"
        d="M20 14h10v34H20z"
      ></path>
      <path fill="none" d="M0 0h50v50H0z"></path>
      <path
        d="M20 23H4v25h42V23H30"
        fill="none"
        stroke="currentColor"
        strokeLinecap="round"
        stroke-miterlimit="10"
        strokeWidth="2"
      ></path>
      <path
        d="M25 13h-8c-4.418 0-9-2.581-9-7 0-1.828.878-4 4.319-4C19.236 2 19.363 13 25 13zM25 13h8c4.418 0 9-2.581 9-7 0-1.828-.878-4-4.319-4C30.764 2 30.637 13 25 13z"
        fill="none"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        stroke-miterlimit="10"
        strokeWidth="2"
      ></path>
    </svg>
  );
};
export default GiftIcon;
