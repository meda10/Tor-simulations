// -----------------------------------------------------------------
// authors: Ing. Libor Polčák Ph.D.
// Source:	http://www.fit.vutbr.cz/~ipolcak/toranim/toranim.html#2
// -----------------------------------------------------------------

function show_layer(num) {
	var layers = document.querySelectorAll("svg g.layer");
	if (layers.length > 0) {
		layers[num].classList.remove("hidden");

		var button_prev = document.getElementById("button_prev");
		var button = document.getElementById("button_next");

		var prev_num = (num - 1);
		var next_num = (num + 1) % layers.length;

		if (prev_num < 0 ){
			prev_num = layers.length - 1;
		}

		button_prev.onclick = show_prev.bind(null, prev_num);
		button.onclick = show_next.bind(null, next_num);

		function show_next(next_num) {
			$("#current_num").html(next_num);
			layers[num].classList.add("hidden");
			show_layer(next_num);
		}

		function show_prev(prev_num) {
			$("#current_num").html(prev_num);
			layers[num].classList.add("hidden");
			show_layer(prev_num);
		}
	}
}

document.addEventListener("DOMContentLoaded", function () {
	var layers = document.querySelectorAll("svg g.layer");
	[].forEach.call(layers, e => e.classList.add("hidden"));
	var layer = parseInt(window.location.hash.substr(1));

	if(layers.length > 0){
		$('#button_prev').prop("disabled", false);
		$('#button_next').prop("disabled", false);
	}

	//var button_prev = document.getElementById("button_prev");
	//button_prev.className='btn btn-primary';
	//button_prev.id = 'button_prev';
	//document.getElementById("link-container").appendChild(button_prev);
	//$("#button_prev").html('Prev');

	//var button = document.getElementById("button_next");
	//button.className='btn btn-primary';
	//button.id = 'button_next';
	//document.getElementById("link-container").appendChild(button);
	//$("#button_next").html('Next');

	if (layer !== "NaN" && layer < layers.length) {
		show_layer(layer);
		$("#current_num").html(layer);
	} else {
		show_layer(0);
		$("#current_num").html('0');
	}
});


/*
function show_layer(num) {
	var layers = document.querySelectorAll("svg g.layer");

	if (layers.length > 0) {
		layers[num].classList.remove("hidden");
		var button = document.createElement("button");
		button.className='btn btn-primary';
		var link = document.createElement("a");
		button.appendChild(link);

		function show_next(next_num) {
			document.getElementById("link-container").removeChild(button);
			layers[num].classList.add("hidden");
			show_layer(next_num);
		}

		var next_num = (num + 1) % layers.length;
		link.onclick = show_next.bind(null, next_num);
		link.href = "#" + next_num;
		link.text = next_num == 0 ? "Restart" : "Next";
		document.getElementById("link-container").appendChild(button);
	}
}

document.addEventListener("DOMContentLoaded", function () {
	var layers = document.querySelectorAll("svg g.layer");
	[].forEach.call(layers, e => e.classList.add("hidden"));
	var layer = parseInt(window.location.hash.substr(1));
	if (layer !== "NaN" && layer < layers.length) {
		show_layer(layer);
	} else {
		show_layer(0);
	}
});

*/