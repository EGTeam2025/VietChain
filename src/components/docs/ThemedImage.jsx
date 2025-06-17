import Image from "next/image";
import { useTheme } from "nextra-theme-docs";

export function ThemedImage(props) {
  const { theme } = useTheme();
  const { darkImage, ...rest } = props;
  if (theme === "dark") {
    return <Image {...rest} src={darkImage} />;
  } else {
    return <Image {...rest} />;
  }
}
