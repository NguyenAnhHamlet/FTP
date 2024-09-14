#ifndef PUT_NUM
#define PUT_NUM


#define GET_32BIT(cp) (((unsigned long)(unsigned char)(cp)[0] << 24) | \
  		       ((unsigned long)(unsigned char)(cp)[1] << 16) | \
		       ((unsigned long)(unsigned char)(cp)[2] << 8) | \
		       ((unsigned long)(unsigned char)(cp)[3]))

#define GET_16BIT(cp) (((unsigned long)(unsigned char)(cp)[0] << 8) | \
		       ((unsigned long)(unsigned char)(cp)[1]))

#define PUT_32BIT(cp, value) do { \
  (cp)[0] = (value) >> 24; \
  (cp)[1] = (value) >> 16; \
  (cp)[2] = (value) >> 8; \
  (cp)[3] = (value); } while (0)

#define PUT_16BIT(cp, value) do { \
  (cp)[0] = (value) >> 8; \
  (cp)[1] = (value); } while (0)

#endif