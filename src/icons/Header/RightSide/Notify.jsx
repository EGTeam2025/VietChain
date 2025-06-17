const NotifyIcon = (props) => {
  return (
    <svg
      height="20px"
      width="20px"
      viewBox="1 -1 100 100"
      className={`fill-current ${props.color}`}
      xmlns="http://www.w3.org/2000/svg"
      enableBackground="new 1 -1 100 100"
    >
      <path
        d="M82.5 57.9V37.6C82.5 20.1 68.4 6 50.9 6S19.4 20.1 19.4 37.6v20.3l-8.2 16.2h79.7l-8.4-16.2zM50.9 92.1c7.3 0 13.3-6 13.3-13.3H37.6c0 7.3 6 13.3 13.3 13.3z"
        fill="currentColor"
      ></path>
    </svg>
  );
};
export default NotifyIcon;
