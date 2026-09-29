use indicatif::{ProgressBar, ProgressStyle};

pub fn print_banner() {
    #[cfg(windows)]
    colored::control::set_virtual_terminal(true).unwrap();
}

pub fn print_end_banner() {}

pub fn progress_bar(
	pb: ProgressBar,
	message: String,
	count: u64,
    end_message: String,
) {
	pb.set_style(ProgressStyle::with_template("{prefix:.bold.dim}{spinner} {wide_msg}")
		.unwrap()
        .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "));
	pb.inc(count);
	pb.with_message(format!("{}: {}{}",message,count,end_message));
}
