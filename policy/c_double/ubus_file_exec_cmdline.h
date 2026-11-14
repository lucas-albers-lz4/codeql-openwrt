/* Typed argv input for the rpcd fallback ACL-string loop, not execv.
 * Unlike this entry point, the legacy pre-joined decide interface cannot
 * recover argument types or counts, or distinguish [] from [""].
 * The includer supplies RPC_CMDLINE_MAX_SIZE and the standard C headers.
 */
static int cmd_cmdline(int argc, char **argv)
{
	char cmdstr[RPC_CMDLINE_MAX_SIZE];
	size_t size;
	int i, arglen = 2;

	if (argc < 1) {
		fprintf(stderr, "cmdline: expected executable and typed args\n");
		return 2;
	}
	size = strlen(argv[0]);
	if (size >= sizeof(cmdstr))
		goto denied;
	memcpy(cmdstr, argv[0], size + 1);
	for (i = 1; i < argc; i++) {
		const char *value = argv[i];
		size_t data_len;

		if (strncmp(value, "n:", 2) == 0)
			continue;
		if (strncmp(value, "s:", 2) != 0) {
			fprintf(stderr, "cmdline: expected s: or n: argument\n");
			return 2;
		}
		value += 2;
		data_len = strlen(value) + 1;
		if (arglen == 255 || data_len >= sizeof(cmdstr) - size)
			goto denied;
		cmdstr[size++] = ' ';
		memcpy(cmdstr + size, value, data_len);
		size += data_len - 1;
		arglen++;
	}
	puts(cmdstr);
	return 0;

denied:
	puts("UBUS_PERMISSION_DENIED");
	return 1;
}
