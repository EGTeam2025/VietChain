import { ThemedImage } from "./ThemedImage";

export function Logo() {
  return (
    <a href="/">
      <ThemedImage
        height={70}
        width={270}
        src="/assets/images/docs/logo/vietchain.svg"
        darkImage={"/assets/images/docs/logo/vietchain.svg"}
        alt="VietChain"
      />
    </a>
  );
}
